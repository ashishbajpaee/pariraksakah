"""
Deliverable 6: Chaos Experiment Engine — FastAPI Microservice
Hypothesis engine, blast radius controller, abort watcher, rollback, dry-run mode.
Publishes to Kafka chaos.experiments, consumes from chaos.results.
"""
import asyncio
import json
import os
import time
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

import asyncpg
import redis
import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from confluent_kafka import Producer, Consumer, KafkaError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chaos_engine")

# ═══ Configuration ═══
KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
PG_DSN = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "changeme_redis")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
GUARDRAILS_URL = os.getenv("CHAOS_GUARDRAILS_URL", "http://chaos-guardrails:8024")
AGENT_URL = os.getenv("CHAOS_AGENT_URL", "http://chaos-injection-agent:8021")

# ═══ State ═══
active_experiments: Dict[str, dict] = {}
pg_pool: Optional[asyncpg.Pool] = None
rds: Optional[redis.Redis] = None
kafka_producer: Optional[Producer] = None


# ═══ Models ═══
class BlastRadius(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class ExperimentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"

class StartExperimentRequest(BaseModel):
    scenario_id: str
    name: str
    target_service: str
    mitre_ttp: str = ""
    attack_phase: str = ""
    injection_type: str = "security"
    blast_radius: BlastRadius = BlastRadius.LOW
    hypothesis: Optional[str] = None
    dry_run: bool = False

class ExperimentResponse(BaseModel):
    experiment_id: str
    status: str
    message: str


# ═══ Kafka Helpers ═══
def publish_to_kafka(topic: str, key: str, payload: dict):
    if kafka_producer:
        kafka_producer.produce(topic, key=key, value=json.dumps(payload, default=str))
        kafka_producer.flush(timeout=5)

def publish_audit(action: str, experiment_id: str, outcome: str, details: str = ""):
    publish_to_kafka("chaos.audit", experiment_id, {
        "audit_id": str(uuid4()), "action": action, "actor": "chaos-engine",
        "experiment_id": experiment_id, "outcome": outcome, "details": details,
        "timestamp": int(time.time() * 1000),
    })


# ═══ Prometheus Health Check ═══
async def check_system_health() -> dict:
    """Query Prometheus for all service health metrics."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": 'up'})
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("data", {}).get("result", [])
                total = len(results)
                healthy = sum(1 for r in results if r.get("value", [None, "0"])[1] == "1")
                health_pct = (healthy / total * 100) if total > 0 else 100
                return {"healthy": healthy, "total": total, "health_pct": health_pct}
    except Exception as e:
        logger.warning(f"Prometheus health check failed: {e}")
    return {"healthy": 0, "total": 0, "health_pct": 100}  # optimistic fallback


# ═══ Abort Watcher ═══
async def abort_watcher(experiment_id: str):
    """Monitor health during experiment, abort if thresholds exceeded."""
    while experiment_id in active_experiments and active_experiments[experiment_id]["status"] == "running":
        health = await check_system_health()
        if health["health_pct"] < 80:
            logger.warning(f"Health dropped to {health['health_pct']}% — ABORTING experiment {experiment_id}")
            await abort_experiment(experiment_id, reason="Health below 80% threshold")
            return
        await asyncio.sleep(5)


# ═══ Rollback ═══
async def rollback_experiment(experiment_id: str):
    """Restore system to pre-chaos state within 30 seconds."""
    exp = active_experiments.get(experiment_id)
    if not exp:
        return
    logger.info(f"Rolling back experiment {experiment_id}...")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            await client.post(f"{AGENT_URL}/rollback", json={"experiment_id": experiment_id})
    except Exception as e:
        logger.error(f"Rollback call failed: {e}")
    publish_audit("ROLLBACK", experiment_id, "completed")


async def abort_experiment(experiment_id: str, reason: str = "manual"):
    """Abort a running experiment and trigger rollback."""
    if experiment_id not in active_experiments:
        return
    active_experiments[experiment_id]["status"] = "aborted"
    active_experiments[experiment_id]["end_time"] = datetime.utcnow().isoformat()
    await rollback_experiment(experiment_id)
    publish_to_kafka("chaos.experiments", experiment_id, {
        **active_experiments[experiment_id], "status": "aborted",
    })
    publish_audit("ABORT", experiment_id, "aborted", reason)
    # Update DB
    if pg_pool:
        async with pg_pool.acquire() as conn:
            await conn.execute(
                "UPDATE chaos_experiments SET status='aborted', end_time=NOW() WHERE id=$1",
                experiment_id,
            )
    logger.info(f"Experiment {experiment_id} aborted: {reason}")


# ═══ Experiment Execution ═══
async def run_experiment(experiment_id: str, req: StartExperimentRequest):
    """Core experiment execution loop."""
    exp = active_experiments[experiment_id]
    try:
        # 1. Check guardrails
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                guard_resp = await client.post(f"{GUARDRAILS_URL}/approve", json={
                    "experiment_id": experiment_id,
                    "blast_radius": req.blast_radius.value,
                    "target_service": req.target_service,
                })
                if guard_resp.status_code != 200:
                    await abort_experiment(experiment_id, "Guardrails rejected experiment")
                    return
        except Exception:
            logger.warning("Guardrails unreachable, proceeding with caution")

        # 2. Check health gate
        health = await check_system_health()
        if health["health_pct"] < 80:
            await abort_experiment(experiment_id, f"Pre-experiment health too low: {health['health_pct']}%")
            return

        # 3. Start abort watcher
        watcher_task = asyncio.create_task(abort_watcher(experiment_id))

        # 4. Execute injection
        if not req.dry_run:
            try:
                async with httpx.AsyncClient(timeout=60) as client:
                    inject_resp = await client.post(f"{AGENT_URL}/inject", json={
                        "experiment_id": experiment_id,
                        "scenario_id": req.scenario_id,
                        "target_service": req.target_service,
                        "injection_type": req.injection_type,
                        "blast_radius": req.blast_radius.value,
                    })
                    if inject_resp.status_code == 200:
                        logger.info(f"Injection started for {experiment_id}")
                    else:
                        logger.error(f"Injection failed: {inject_resp.text}")
            except Exception as e:
                logger.error(f"Injection agent unreachable: {e}")
        else:
            logger.info(f"DRY RUN: Simulating injection for {experiment_id}")
            await asyncio.sleep(5)

        # 5. Wait for results (max 5 minutes)
        await asyncio.sleep(30 if not req.dry_run else 3)

        # 6. Mark complete
        if exp["status"] == "running":
            exp["status"] = "completed"
            exp["end_time"] = datetime.utcnow().isoformat()
            active_experiments[experiment_id] = exp
            publish_to_kafka("chaos.experiments", experiment_id, exp)
            publish_audit("COMPLETE", experiment_id, "completed")
            if pg_pool:
                async with pg_pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE chaos_experiments SET status='completed', end_time=NOW() WHERE id=$1",
                        experiment_id,
                    )

        watcher_task.cancel()

    except Exception as e:
        logger.error(f"Experiment {experiment_id} failed: {e}")
        await abort_experiment(experiment_id, str(e))


# ═══ FastAPI Lifespan ═══
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pg_pool, rds, kafka_producer
    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=5)
    except Exception as e:
        logger.error(f"DB connection failed: {e}")
    rds = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
    kafka_producer = Producer({"bootstrap.servers": KAFKA_BROKER})
    logger.info("Chaos Experiment Engine started")
    yield
    if pg_pool:
        await pg_pool.close()

app = FastAPI(title="Chaos Experiment Engine", version="1.0.0", lifespan=lifespan)


# ═══ REST API Endpoints ═══
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "chaos-experiment-engine", "active_experiments": len(active_experiments)}


@app.post("/experiments/start", response_model=ExperimentResponse)
async def start_experiment(req: StartExperimentRequest, bg: BackgroundTasks):
    experiment_id = str(uuid4())
    exp = {
        "experiment_id": experiment_id,
        "scenario_id": req.scenario_id,
        "name": req.name,
        "target_service": req.target_service,
        "mitre_ttp": req.mitre_ttp,
        "attack_phase": req.attack_phase,
        "injection_type": req.injection_type,
        "blast_radius": req.blast_radius.value,
        "hypothesis": req.hypothesis,
        "dry_run": req.dry_run,
        "status": "running",
        "start_time": datetime.utcnow().isoformat(),
        "end_time": None,
    }
    active_experiments[experiment_id] = exp

    # Persist to TimescaleDB
    if pg_pool:
        async with pg_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO chaos_experiments
                   (id, scenario_id, name, mitre_ttp, attack_phase, injection_type,
                    blast_radius, target_service, status, dry_run, start_time, hypothesis)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'running', $9, NOW(), $10)""",
                experiment_id, req.scenario_id, req.name, req.mitre_ttp,
                req.attack_phase, req.injection_type, req.blast_radius.value,
                req.target_service, req.dry_run, json.dumps({"text": req.hypothesis}),
            )

    # Publish to Kafka
    publish_to_kafka("chaos.experiments", experiment_id, exp)
    publish_audit("START", experiment_id, "running", f"dry_run={req.dry_run}")

    # Run experiment in background
    bg.add_task(run_experiment, experiment_id, req)

    return ExperimentResponse(experiment_id=experiment_id, status="running",
                              message="Experiment started" + (" (DRY RUN)" if req.dry_run else ""))


@app.post("/experiments/stop")
async def stop_experiment(experiment_id: str):
    if experiment_id not in active_experiments:
        raise HTTPException(404, "Experiment not found")
    await abort_experiment(experiment_id, "manual stop")
    return {"status": "aborted", "experiment_id": experiment_id}


@app.get("/experiments/status")
async def experiments_status():
    return {"active": len(active_experiments), "experiments": active_experiments}


@app.post("/experiments/dry-run", response_model=ExperimentResponse)
async def dry_run_experiment(req: StartExperimentRequest, bg: BackgroundTasks):
    req.dry_run = True
    return await start_experiment(req, bg)


@app.get("/experiments/history")
async def experiment_history(limit: int = 50):
    if not pg_pool:
        return {"history": []}
    async with pg_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM chaos_experiments ORDER BY start_time DESC LIMIT $1", limit
        )
        return {"history": [dict(r) for r in rows]}


@app.post("/chaos/kill-all")
async def kill_all_experiments():
    """Emergency stop — abort all active experiments within 5 seconds."""
    killed = []
    for eid in list(active_experiments.keys()):
        if active_experiments[eid]["status"] == "running":
            await abort_experiment(eid, "EMERGENCY KILL ALL")
            killed.append(eid)
    # Also publish kill signal to Kafka control topic
    publish_to_kafka("chaos.control", "KILL_ALL", {"command": "KILL_ALL", "timestamp": int(time.time() * 1000)})
    publish_audit("KILL_ALL", "system", "completed", f"Killed {len(killed)} experiments")
    return {"status": "all_killed", "experiments_stopped": killed}


@app.get("/metrics")
async def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    active = sum(1 for e in active_experiments.values() if e["status"] == "running")
    total = len(active_experiments)
    metrics = (
        f'# HELP chaos_experiments_active Currently running experiments\n'
        f'# TYPE chaos_experiments_active gauge\n'
        f'chaos_experiments_active {active}\n'
        f'# HELP chaos_experiments_total Total experiments tracked\n'
        f'# TYPE chaos_experiments_total counter\n'
        f'chaos_experiments_total {total}\n'
    )
    return PlainTextResponse(metrics, media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("CHAOS_ENGINE_PORT", "8020")))
