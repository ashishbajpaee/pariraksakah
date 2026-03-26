"""
Deliverable 3 (behavioral) — UEBA Behavioral Analysis Engine
Dynamic baseline per user/service, deviation scoring, real-time
risk score updates via Redis sorted sets, Kafka event consumption.
"""
import os, json, math, logging, asyncio
from datetime import datetime
from typing import Any, Dict, Optional
from contextlib import asynccontextmanager

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

log = logging.getLogger("behavioral-engine")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [UEBA] %(message)s")

PG_DSN    = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
REDIS_URL = f"redis://:{os.getenv('REDIS_PASSWORD','changeme_redis')}@{os.getenv('REDIS_HOST','redis')}:{os.getenv('REDIS_PORT','6379')}"

RISK_WEIGHTS = {
    "failed_auth_count":           5.0,
    "off_hours_flag":              8.0,
    "unusual_geo_flag":           12.0,
    "lateral_hop_count":          15.0,
    "bytes_out_mb":                0.5,   # per MB
    "priv_escalation_attempts":   20.0,
    "new_user_agent_flag":         6.0,
    "api_call_rate_per_min":       0.2,   # per req/min above baseline
    "distinct_ips":                3.0,
}

ESCALATION_THRESHOLDS = {
    "low":      25.0,
    "medium":   50.0,
    "high":     70.0,
    "critical": 85.0,
}


class BehavioralEvent(BaseModel):
    entity_id: str
    entity_type: str     # "user" | "service" | "network"
    event_type: str      # "auth", "api_call", "file_access", "network"
    features: Dict[str, float]
    source_ip: Optional[str] = None
    geo_country: Optional[str] = None
    timestamp: str = ""


class EntityBaseline(BaseModel):
    entity_id: str
    entity_type: str
    avg_login_hour: float      = 10.0
    avg_api_rate:   float      = 20.0
    typical_country: str       = "IN"
    avg_bytes_out:  float      = 1.0
    sample_count:   int        = 0
    last_updated:   str        = ""


class RiskProfile(BaseModel):
    entity_id: str
    risk_score: float          # 0-100
    risk_level: str            # low | medium | high | critical
    top_signals: Dict[str, float]
    escalated: bool
    last_event_ts: str


class BaselineStore:
    """In-memory exponential moving average store for entity baselines."""

    def __init__(self):
        self._store: Dict[str, EntityBaseline] = {}
        self._alpha = 0.1  # EMA smoothing factor

    def get(self, entity_id: str) -> EntityBaseline:
        return self._store.get(entity_id, EntityBaseline(
            entity_id=entity_id, entity_type="unknown"))

    def update(self, entity_id: str, event: BehavioralEvent):
        b = self._store.get(entity_id)
        if b is None:
            b = EntityBaseline(entity_id=entity_id,
                               entity_type=event.entity_type,
                               last_updated=datetime.utcnow().isoformat())
        a = self._alpha
        b.avg_api_rate   = (1 - a) * b.avg_api_rate   + a * event.features.get("api_call_rate_per_min", b.avg_api_rate)
        b.avg_bytes_out  = (1 - a) * b.avg_bytes_out  + a * event.features.get("bytes_out_mb", b.avg_bytes_out)
        b.avg_login_hour = (1 - a) * b.avg_login_hour + a * event.features.get("login_hour", b.avg_login_hour)
        if event.geo_country:
            if b.typical_country == "unknown" or b.sample_count < 5:
                b.typical_country = event.geo_country
        b.sample_count += 1
        b.last_updated = datetime.utcnow().isoformat()
        self._store[entity_id] = b


baseline_store = BaselineStore()
pg_pool: Optional[asyncpg.Pool] = None
rds:     Optional[aioredis.Redis] = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS entity_risk_scores (
    entity_id TEXT PRIMARY KEY,
    risk_score DOUBLE PRECISION,
    risk_level TEXT,
    escalated  BOOLEAN,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
"""

_DRIFT_TABLE = """
CREATE TABLE IF NOT EXISTS model_drift_log (
    id SERIAL PRIMARY KEY,
    metric TEXT, value DOUBLE PRECISION,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def _compute_risk(event: BehavioralEvent, baseline: EntityBaseline) -> RiskProfile:
    score = 0.0
    signals: Dict[str, float] = {}

    for feat, weight in RISK_WEIGHTS.items():
        val = event.features.get(feat, 0.0)
        contribution = val * weight
        if contribution > 0:
            signals[feat] = round(contribution, 2)
            score += contribution

    # Geo deviation bonus
    if event.geo_country and event.geo_country != baseline.typical_country:
        signals["geo_deviation"] = 15.0
        score += 15.0

    # Baseline deviation bonus
    api_dev = abs(event.features.get("api_call_rate_per_min", 0) - baseline.avg_api_rate)
    if api_dev > baseline.avg_api_rate * 2:
        signals["api_rate_spike"] = round(api_dev * 0.3, 2)
        score += api_dev * 0.3

    score = min(score, 100.0)

    level = "low"
    for lv, threshold in sorted(ESCALATION_THRESHOLDS.items(),
                                 key=lambda x: x[1], reverse=True):
        if score >= threshold:
            level = lv
            break

    return RiskProfile(
        entity_id=event.entity_id,
        risk_score=round(score, 2),
        risk_level=level,
        top_signals=dict(sorted(signals.items(), key=lambda x: -x[1])[:5]),
        escalated=level in ("high", "critical"),
        last_event_ts=event.timestamp or datetime.utcnow().isoformat(),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pg_pool, rds
    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=1, max_size=3)
        async with pg_pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL + _DRIFT_TABLE)
    except Exception as e:
        log.error(f"DB init failed: {e}")
    try:
        rds = aioredis.from_url(REDIS_URL, decode_responses=True)
    except Exception as e:
        log.error(f"Redis init failed: {e}")
    log.info("UEBA Behavioral Engine online ✓")
    yield
    if pg_pool: await pg_pool.close()


app = FastAPI(title="UEBA Behavioral Analysis Engine", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "behavioral-analysis-engine",
            "baselines_tracked": len(baseline_store._store)}


@app.post("/analyze", response_model=RiskProfile)
async def analyze(event: BehavioralEvent):
    """Process a behavioral event, update baseline, return risk profile."""
    if not event.timestamp:
        event.timestamp = datetime.utcnow().isoformat()

    baseline = baseline_store.get(event.entity_id)
    profile  = _compute_risk(event, baseline)

    # Update baseline EMA
    baseline_store.update(event.entity_id, event)

    # Persist risk score
    if pg_pool:
        try:
            async with pg_pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO entity_risk_scores(entity_id, risk_score, risk_level, escalated)
                       VALUES($1,$2,$3,$4)
                       ON CONFLICT(entity_id) DO UPDATE
                       SET risk_score=$2, risk_level=$3, escalated=$4, updated_at=NOW()""",
                    profile.entity_id, profile.risk_score,
                    profile.risk_level, profile.escalated
                )
        except Exception as e:
            log.error(f"DB write failed: {e}")

    # Redis sorted set for real-time leaderboard
    if rds:
        await rds.zadd("ueba:risk_scores", {event.entity_id: profile.risk_score})
        if profile.escalated:
            await rds.publish("ueba:escalations", json.dumps({
                "entity_id": event.entity_id,
                "risk_score": profile.risk_score,
                "risk_level": profile.risk_level,
                "top_signals": profile.top_signals,
            }))

    if profile.escalated:
        log.warning(f"[ESCALATION] {event.entity_id} risk={profile.risk_score} level={profile.risk_level}")

    return profile


@app.get("/entities/{entity_id}/baseline")
async def get_baseline(entity_id: str):
    return baseline_store.get(entity_id).model_dump()


@app.get("/entities/top-risk")
async def top_risk_entities(limit: int = 10):
    if rds:
        results = await rds.zrevrangebyscore(
            "ueba:risk_scores", "+inf", "-inf",
            withscores=True, start=0, num=limit
        )
        return {"entities": [{"entity_id": e, "risk_score": s} for e, s in results]}
    return {"entities": []}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    count = len(baseline_store._store)
    return (f"ueba_tracked_entities {count}\n"
            f"ueba_baselines_count {count}\n")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0",
                port=int(os.getenv("BEHAVIORAL_PORT", "8042")))
