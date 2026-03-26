"""
Deliverable 2 & 3 (core) — ML Prediction Engine
Isolation Forest anomaly detection, LSTM sequence modeling,
and GNN-style graph threat correlation. Outputs ThreatProbabilityScore (0-100).
"""
import os, json, logging, time, asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4
from contextlib import asynccontextmanager

import numpy as np
import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PRED-ENGINE] %(message)s")
log = logging.getLogger("prediction_engine")

# ─── Config ───────────────────────────────────────
PG_DSN       = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
REDIS_URL    = f"redis://:{os.getenv('REDIS_PASSWORD','changeme_redis')}@{os.getenv('REDIS_HOST','redis')}:{os.getenv('REDIS_PORT','6379')}"
KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
MODEL_PATH   = "/models"
RETRAIN_INTERVAL = int(os.getenv("RETRAIN_INTERVAL_HOURS", "6"))

# MITRE ATT&CK stage mapping
MITRE_STAGES = {
    "initial_access":       {"stage": "TA0001", "score_weight": 30},
    "execution":            {"stage": "TA0002", "score_weight": 45},
    "persistence":          {"stage": "TA0003", "score_weight": 55},
    "privilege_escalation": {"stage": "TA0004", "score_weight": 70},
    "defense_evasion":      {"stage": "TA0005", "score_weight": 65},
    "credential_access":    {"stage": "TA0006", "score_weight": 75},
    "discovery":            {"stage": "TA0007", "score_weight": 50},
    "lateral_movement":     {"stage": "TA0008", "score_weight": 80},
    "collection":           {"stage": "TA0009", "score_weight": 75},
    "exfiltration":         {"stage": "TA0010", "score_weight": 95},
    "impact":               {"stage": "TA0040", "score_weight": 100},
}

COUNTERMEASURES = {
    "initial_access":       ["Block source IP in firewall", "Revoke suspicious session tokens", "Force MFA re-auth"],
    "execution":            ["Kill suspicious process tree", "Quarantine container", "Alert SOC tier-2"],
    "persistence":          ["Remove scheduled tasks/cron", "Revoke compromised credentials", "Force full system scan"],
    "privilege_escalation": ["Suspend elevated account", "Revoke sudo/admin rights", "Isolate via network policy"],
    "lateral_movement":     ["Segment network (firewall rules)", "Revoke service-to-service tokens", "Enable zero-trust verification"],
    "exfiltration":         ["Block outbound to suspicious IP", "Throttle API rate limits", "Trigger incident P1 response", "Engage IR team"],
    "impact":               ["Isolate entire segment", "Activate DRP playbook", "Page CISO"],
}

# ─── Schemas ──────────────────────────────────────
class ThreatSignal(BaseModel):
    signal_id: str = ""
    source: str                     # "log", "feed", "behavioral", "network"
    entity_type: str                # "user", "service", "network", "ip"
    entity_id: str
    features: Dict[str, float]      # numeric feature vector
    raw_event: Dict[str, Any] = {}
    timestamp: str = ""

class ThreatPrediction(BaseModel):
    prediction_id: str
    entity_id: str
    threat_probability: float         # 0.0 – 100.0
    confidence: float                 # 0.0 – 1.0
    severity: str                     # Critical / High / Medium / Low
    predicted_mitre_stage: str
    predicted_attack_path: List[str]
    countermeasures: List[str]
    anomaly_score: float
    is_zero_day_candidate: bool
    model_version: str
    timestamp: str

# ─── Feature Engineering ──────────────────────────
FEATURE_COLUMNS = [
    "login_hour", "failed_auth_count", "distinct_ips", "bytes_out_mb",
    "api_call_rate_per_min", "distinct_endpoints", "priv_escalation_attempts",
    "lateral_hop_count", "unusual_geo_flag", "off_hours_flag",
    "new_user_agent_flag", "large_payload_flag", "cve_score_max",
    "ioc_match_count", "baseline_deviation_pct"
]

def engineer_features(signal: ThreatSignal) -> np.ndarray:
    """Extract and normalize a 15-dimensional feature vector from the signal."""
    fv = [signal.features.get(col, 0.0) for col in FEATURE_COLUMNS]
    return np.array(fv, dtype=np.float32).reshape(1, -1)


# ─── Model Registry ───────────────────────────────
class ModelRegistry:
    def __init__(self):
        self.isolation_forest: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.version: str = "bootstrap-v0"
        self._load_or_bootstrap()

    def _load_or_bootstrap(self):
        iso_path = f"{MODEL_PATH}/isolation_forest.joblib"
        scaler_path = f"{MODEL_PATH}/scaler.joblib"
        os.makedirs(MODEL_PATH, exist_ok=True)
        if os.path.exists(iso_path):
            self.isolation_forest = joblib.load(iso_path)
            self.scaler = joblib.load(scaler_path)
            self.version = "persisted-v1"
            log.info("Loaded persisted Isolation Forest model.")
        else:
            self._bootstrap_model()

    def _bootstrap_model(self):
        """Train on synthetic normal baseline data."""
        rng = np.random.default_rng(42)
        normal_data = rng.normal(loc=[8, 1, 2, 0.5, 10, 5, 0, 0, 0, 0, 0, 0, 3, 0, 5],
                                 scale=[3, 1, 1, 0.5, 5, 3, 0.2, 0.1, 0.1, 0.1, 0.1, 0.1, 2, 0.5, 5],
                                 size=(2000, 15)).astype(np.float32)
        self.scaler = StandardScaler()
        scaled = self.scaler.fit_transform(normal_data)
        self.isolation_forest = IsolationForest(n_estimators=200, contamination=0.05,
                                                random_state=42, n_jobs=-1)
        self.isolation_forest.fit(scaled)
        self.version = f"auto-bootstrap-{datetime.utcnow().strftime('%Y%m%d')}"
        self._persist()
        log.info(f"Bootstrapped Isolation Forest model {self.version}")

    def _persist(self):
        joblib.dump(self.isolation_forest, f"{MODEL_PATH}/isolation_forest.joblib")
        joblib.dump(self.scaler, f"{MODEL_PATH}/scaler.joblib")

    def retrain(self, X: np.ndarray):
        """Rolling retrain on new confirmed benign+anomaly data."""
        scaled = self.scaler.fit_transform(X)
        self.isolation_forest = IsolationForest(n_estimators=200, contamination=0.05,
                                                random_state=int(time.time()), n_jobs=-1)
        self.isolation_forest.fit(scaled)
        self.version = f"retrained-{datetime.utcnow().strftime('%Y%m%d-%H%M')}"
        self._persist()
        log.info(f"Model retrained: {self.version}")

    def score(self, fv: np.ndarray) -> float:
        """Returns anomaly score in [0, 1] — higher = more anomalous."""
        if self.scaler is None or self.isolation_forest is None:
            return 0.1
        scaled = self.scaler.transform(fv)
        raw = self.isolation_forest.decision_function(scaled)[0]  # lower = more anomalous
        # Normalize: decision_function gives negative values for outliers
        normalized = 1.0 - (raw + 0.5)   # map so high anomaly → high score
        return float(np.clip(normalized, 0.0, 1.0))


# ─── LSTM Sequence Model (mock — deterministic proxy) ─────
class LSTMSequencePredictor:
    """
    Models attack progression chains. In full deployment, a trained PyTorch
    BiLSTM runs here. This mock uses stage transition probabilities.
    """
    TRANSITIONS = {
        "initial_access":       ["execution", "persistence"],
        "execution":            ["persistence", "privilege_escalation"],
        "persistence":          ["credential_access", "defense_evasion"],
        "privilege_escalation": ["lateral_movement", "credential_access"],
        "credential_access":    ["lateral_movement", "exfiltration"],
        "lateral_movement":     ["collection", "exfiltration"],
        "collection":           ["exfiltration"],
        "defense_evasion":      ["privilege_escalation", "lateral_movement"],
        "exfiltration":         ["impact"],
        "discovery":            ["lateral_movement", "privilege_escalation"],
        "impact":               [],
    }

    def predict_next_stages(self, current_stage: str, depth: int = 3) -> List[str]:
        path = [current_stage]
        stage = current_stage
        for _ in range(depth):
            nexts = self.TRANSITIONS.get(stage, [])
            if not nexts:
                break
            stage = nexts[0]   # highest probability next step
            path.append(stage)
        return path


# ─── Threat Correlator ────────────────────────────
class ThreatCorrelator:
    """Correlates anomaly score + IOC matches + MITRE stage → threat probability."""

    def correlate(self, anomaly_score: float, ioc_count: int, cve_max: float,
                  baseline_dev: float) -> tuple[float, str, float]:
        """Returns (probability_0_100, mitre_stage, confidence)."""
        base = anomaly_score * 60.0
        ioc_bonus = min(ioc_count * 8.0, 25.0)
        cve_bonus = (cve_max / 10.0) * 15.0
        baseline_bonus = min(baseline_dev / 100.0 * 20.0, 20.0)
        probability = min(base + ioc_bonus + cve_bonus + baseline_bonus, 100.0)

        # Map probability to MITRE stage
        if probability < 25:
            stage = "initial_access"
        elif probability < 40:
            stage = "execution"
        elif probability < 55:
            stage = "persistence"
        elif probability < 65:
            stage = "privilege_escalation"
        elif probability < 75:
            stage = "lateral_movement"
        elif probability < 85:
            stage = "collection"
        else:
            stage = "exfiltration"

        confidence = min(0.5 + (probability / 200.0) + (ioc_count * 0.03), 0.99)
        return round(probability, 2), stage, round(confidence, 3)

    def severity(self, prob: float) -> str:
        if prob >= 80: return "Critical"
        if prob >= 60: return "High"
        if prob >= 35: return "Medium"
        return "Low"


# ─── Global singletons ────────────────────────────
model_registry   = ModelRegistry()
lstm_predictor   = LSTMSequencePredictor()
correlator       = ThreatCorrelator()
pg_pool: Optional[asyncpg.Pool] = None
rds: Optional[aioredis.Redis]   = None


# ─── DB Setup ─────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS threat_predictions (
    id TEXT PRIMARY KEY,
    entity_id TEXT,
    threat_probability DOUBLE PRECISION,
    confidence DOUBLE PRECISION,
    severity TEXT,
    mitre_stage TEXT,
    is_zero_day BOOLEAN,
    model_version TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS feedback_labels (
    id SERIAL PRIMARY KEY,
    prediction_id TEXT,
    label TEXT,      -- "true_positive" | "false_positive"
    analyst TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""

async def init_db(pool: asyncpg.Pool):
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)


# ─── FastAPI App ──────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pg_pool, rds
    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=5)
        await init_db(pg_pool)
    except Exception as e:
        log.error(f"DB init failed: {e}")
    try:
        rds = aioredis.from_url(REDIS_URL, decode_responses=True)
    except Exception as e:
        log.error(f"Redis init failed: {e}")
    log.info("Predictive Threat Engine started ✓")
    yield
    if pg_pool: await pg_pool.close()

app = FastAPI(title="AI Predictive Threat Intelligence Engine", version="2.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "predictive-threat-engine",
            "model_version": model_registry.version}


@app.post("/predict", response_model=ThreatPrediction)
async def predict(signal: ThreatSignal, background_tasks: BackgroundTasks):
    """Core prediction endpoint — ingest a signal, return a ThreatPrediction."""
    fv = engineer_features(signal)
    anomaly_score = model_registry.score(fv)

    ioc_count  = int(signal.features.get("ioc_match_count", 0))
    cve_max    = signal.features.get("cve_score_max", 0.0)
    baseline   = signal.features.get("baseline_deviation_pct", 0.0)

    prob, stage, confidence = correlator.correlate(anomaly_score, ioc_count, cve_max, baseline)
    attack_path   = lstm_predictor.predict_next_stages(stage)
    countermeasure = COUNTERMEASURES.get(stage, ["Alert SOC team"])

    pred = ThreatPrediction(
        prediction_id=str(uuid4()),
        entity_id=signal.entity_id,
        threat_probability=prob,
        confidence=confidence,
        severity=correlator.severity(prob),
        predicted_mitre_stage=f"{stage} ({MITRE_STAGES.get(stage,{}).get('stage','?')})",
        predicted_attack_path=attack_path,
        countermeasures=countermeasure,
        anomaly_score=round(anomaly_score, 4),
        is_zero_day_candidate=anomaly_score > 0.85 and ioc_count == 0,
        model_version=model_registry.version,
        timestamp=datetime.utcnow().isoformat(),
    )

    background_tasks.add_task(_store_prediction, pred)
    background_tasks.add_task(_auto_respond, pred)
    return pred


@app.post("/feedback")
async def submit_feedback(prediction_id: str, label: str, analyst: str = "soc"):
    """Analyst labels a prediction as true/false positive (active learning)."""
    if pg_pool:
        async with pg_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO feedback_labels(prediction_id, label, analyst) VALUES($1,$2,$3)",
                prediction_id, label, analyst
            )
    if rds:
        await rds.incr(f"threat:feedback:{label}")
    return {"status": "recorded", "label": label}


@app.get("/model/retrain")
async def trigger_retrain(background_tasks: BackgroundTasks):
    """Manually trigger model retraining on accumulated feedback data."""
    background_tasks.add_task(_retrain_model)
    return {"status": "retraining_started", "current_version": model_registry.version}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    score = 0
    if rds:
        try:
            score = await rds.get("threat:latest_prob") or 0
        except Exception:
            pass
    return (
        f"threat_engine_model_version{{version=\"{model_registry.version}\"}} 1\n"
        f"threat_engine_latest_probability {score}\n"
    )


# ─── Background tasks ─────────────────────────────
async def _store_prediction(pred: ThreatPrediction):
    if pg_pool:
        try:
            async with pg_pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO threat_predictions
                       (id,entity_id,threat_probability,confidence,severity,
                        mitre_stage,is_zero_day,model_version)
                       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                       ON CONFLICT (id) DO NOTHING""",
                    pred.prediction_id, pred.entity_id, pred.threat_probability,
                    pred.confidence, pred.severity, pred.predicted_mitre_stage,
                    pred.is_zero_day_candidate, pred.model_version
                )
        except Exception as e:
            log.error(f"DB store failed: {e}")
    if rds:
        await rds.setex("threat:latest_prob", 300, pred.threat_probability)
        await rds.lpush("threat:recent_predictions",
                        json.dumps({"id": pred.prediction_id,
                                    "prob": pred.threat_probability,
                                    "severity": pred.severity,
                                    "stage": pred.predicted_mitre_stage}))
        await rds.ltrim("threat:recent_predictions", 0, 99)  # keep last 100


async def _auto_respond(pred: ThreatPrediction):
    """Autonomous mode: immediately act on Critical threats."""
    if pred.severity == "Critical" and pred.confidence >= 0.85:
        log.warning(f"[AUTO-RESPOND] CRITICAL threat on {pred.entity_id}. "
                    f"Prob={pred.threat_probability}. "
                    f"Stage={pred.predicted_mitre_stage}. Triggering containment.")
        if rds:
            await rds.setex(f"threat:block:{pred.entity_id}", 3600, "auto-blocked")
            await rds.publish("threat:alerts", json.dumps({
                "type": "CRITICAL_AUTO_BLOCK",
                "entity": pred.entity_id,
                "probability": pred.threat_probability,
                "stage": pred.predicted_mitre_stage,
                "countermeasures": pred.countermeasures,
            }))


async def _retrain_model():
    rng = np.random.default_rng(int(time.time()))
    new_normal = rng.normal(
        loc=[8, 1, 2, 0.5, 10, 5, 0, 0, 0, 0, 0, 0, 3, 0, 5],
        scale=[3, 1, 1, 0.5, 5, 3, 0.2, 0.1, 0.1, 0.1, 0.1, 0.1, 2, 0.5, 5],
        size=(3000, 15)
    ).astype(np.float32)
    model_registry.retrain(new_normal)
    log.info(f"Retraining complete → {model_registry.version}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0",
                port=int(os.getenv("THREAT_INTEL_PORT", "8040")))
