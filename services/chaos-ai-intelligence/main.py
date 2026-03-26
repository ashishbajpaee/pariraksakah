"""
Deliverable 10: AI Chaos Intelligence Module
Gap Analyzer, Weakness Predictor, Adaptive Difficulty, Attack Chain Simulator,
and Scenario Mutation Engine — all integrated with MLFlow.
"""
import asyncio
import json
import os
import logging
import time
from contextlib import asynccontextmanager
from typing import List, Optional
from uuid import uuid4

import asyncpg
import httpx
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chaos_ai")

PG_DSN = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme_neo4j")
MLFLOW_URI = os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000")
CHAOS_ENGINE_URL = os.getenv("CHAOS_ENGINE_URL", "http://chaos-experiment-engine:8020")
MITRE_PATH = os.getenv("MITRE_DATASET", "/datasets/mitre/enterprise-attack.json")

pg_pool: Optional[asyncpg.Pool] = None

# ═══ MITRE TTP Loader ═══
def load_mitre_ttps() -> dict:
    """Load all MITRE techniques into a lookup dictionary."""
    ttps = {}
    try:
        if os.path.exists(MITRE_PATH):
            with open(MITRE_PATH) as f:
                bundle = json.load(f)
            for obj in bundle.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    ext_refs = obj.get("external_references", [])
                    mid = next((r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
                    if mid:
                        ttps[mid] = obj.get("name", mid)
    except Exception as e:
        logger.error(f"Failed to load MITRE: {e}")
    if not ttps:
        ttps = {"T1078": "Valid Accounts", "T1190": "Exploit Public-Facing App", "T1021": "Remote Services",
                "T1059": "Command and Scripting Interpreter", "T1053": "Scheduled Task/Job",
                "T1548": "Abuse Elevation Control", "T1070": "Indicator Removal", "T1003": "OS Credential Dumping",
                "T1046": "Network Service Discovery", "T1041": "Exfiltration Over C2 Channel",
                "T1565": "Data Manipulation", "T1557": "Adversary-in-the-Middle", "T1562": "Impair Defenses",
                "T1189": "Drive-by Compromise", "T1195": "Supply Chain Compromise", "T1611": "Escape to Host",
                "T1027": "Obfuscated Files", "T1573": "Encrypted Channel", "T1556": "Modify Authentication Process",
                "T1071": "Application Layer Protocol", "T1505": "Server Software Component",
                "T1499": "Endpoint Denial of Service"}
    return ttps


# ═══ 1. Gap Analyzer ═══
async def analyze_gaps() -> dict:
    """Cross-reference MITRE TTPs against experiment history to identify untested techniques."""
    all_ttps = load_mitre_ttps()
    tested_ttps = set()

    if pg_pool:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch("SELECT DISTINCT mitre_ttp FROM chaos_experiments WHERE status='completed'")
            tested_ttps = {r["mitre_ttp"] for r in rows if r["mitre_ttp"]}

    untested = {ttp: name for ttp, name in all_ttps.items() if ttp not in tested_ttps}
    coverage_pct = ((len(all_ttps) - len(untested)) / max(len(all_ttps), 1)) * 100

    recommended = []
    services = ["api-gateway", "kafka", "timescaledb", "neo4j", "redis", "self-healing", "react-frontend"]
    for ttp, name in list(untested.items())[:10]:
        import random
        recommended.append({
            "scenario_id": str(uuid4()),
            "name": f"Auto-generated: Test {name}",
            "mitre_ttp": ttp,
            "target_service": random.choice(services),
            "blast_radius": "low",
            "injection_type": "security",
            "severity": "medium",
        })

    return {
        "total_mitre_ttps": len(all_ttps),
        "tested_ttps": len(tested_ttps),
        "untested_ttps": len(untested),
        "coverage_pct": round(coverage_pct, 1),
        "recommended_scenarios": recommended,
    }


# ═══ 2. Weakness Predictor ═══
async def predict_weaknesses() -> dict:
    """Train RandomForest on experiment history to predict which service will fail next."""
    if not pg_pool:
        return {"error": "Database not connected"}

    async with pg_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT e.target_service, r.resilience_score, r.containment_score,
                   r.detection_time_ms, r.false_negative_rate
            FROM chaos_results r JOIN chaos_experiments e ON r.experiment_id = e.id
            ORDER BY r.timestamp DESC LIMIT 500
        """)

    if len(rows) < 10:
        return {"message": "Insufficient data for prediction (need 10+ experiments)", "predictions": []}

    service_map = {}
    services = list(set(r["target_service"] for r in rows))
    for i, s in enumerate(services):
        service_map[s] = i

    X = []
    y = []
    for r in rows:
        X.append([r["resilience_score"], r["containment_score"], r["detection_time_ms"], r["false_negative_rate"]])
        y.append(1 if r["resilience_score"] < 70 else 0)  # 1 = likely to fail

    X = np.array(X)
    y = np.array(y)

    if len(set(y)) < 2:
        return {"message": "Not enough variance in outcomes", "predictions": []}

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test)

    # Log to MLFlow
    try:
        import mlflow
        mlflow.set_tracking_uri(MLFLOW_URI)
        mlflow.set_experiment("chaos-weakness-predictor")
        with mlflow.start_run(run_name=f"prediction-{int(time.time())}"):
            mlflow.log_metric("accuracy", accuracy)
            mlflow.log_metric("sample_size", len(rows))
            mlflow.sklearn.log_model(model, "weakness_predictor")
    except Exception as e:
        logger.warning(f"MLFlow logging failed: {e}")

    # Predict per service
    predictions = []
    for svc in services:
        svc_rows = [r for r in rows if r["target_service"] == svc]
        if svc_rows:
            latest = svc_rows[0]
            features = np.array([[latest["resilience_score"], latest["containment_score"],
                                  latest["detection_time_ms"], latest["false_negative_rate"]]])
            prob = model.predict_proba(features)[0]
            fail_prob = prob[1] if len(prob) > 1 else 0
            predictions.append({
                "service": svc,
                "failure_probability": round(float(fail_prob) * 100, 1),
                "confidence": round(float(accuracy) * 100, 1),
                "last_resilience_score": float(latest["resilience_score"]),
            })

    predictions.sort(key=lambda x: x["failure_probability"], reverse=True)
    return {"model_accuracy": round(accuracy * 100, 1), "predictions": predictions}


# ═══ 3. Adaptive Difficulty ═══
async def get_adaptive_recommendations() -> dict:
    """Increase experiment complexity as Resilience Score improves."""
    if not pg_pool:
        return {"recommendations": []}

    async with pg_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT e.target_service, avg(r.resilience_score) as avg_score
            FROM chaos_results r JOIN chaos_experiments e ON r.experiment_id = e.id
            WHERE r.timestamp > NOW() - INTERVAL '7 days'
            GROUP BY e.target_service
        """)

    recommendations = []
    for r in rows:
        score = float(r["avg_score"])
        svc = r["target_service"]
        if score >= 95:
            level = "extreme"
            blast = "high"
            note = "Service is highly resilient. Recommend multi-vector compound attacks."
        elif score >= 85:
            level = "hard"
            blast = "high"
            note = "Service is strong. Escalate to high blast radius scenarios."
        elif score >= 70:
            level = "medium"
            blast = "medium"
            note = "Service is adequate. Maintain current difficulty."
        else:
            level = "easy"
            blast = "low"
            note = "Service is weak. Focus on remediation before increasing difficulty."

        recommendations.append({
            "service": svc,
            "avg_resilience_score": round(score, 1),
            "recommended_difficulty": level,
            "recommended_blast_radius": blast,
            "note": note,
        })

    return {"recommendations": recommendations}


# ═══ 4. Attack Chain Simulator ═══
async def simulate_attack_chain() -> dict:
    """Multi-stage APT simulation: Stage 1 → 2 → 3 → 4, each triggers only if previous succeeds."""
    stages = [
        {"stage": 1, "name": "Initial Access via JWT Forgery", "target": "api-gateway",
         "scenario_id": "a1b2c3d4-0001-4000-8000-000000000001", "mitre_ttp": "T1078.004"},
        {"stage": 2, "name": "Lateral Movement via Kafka Poisoning", "target": "kafka",
         "scenario_id": "a1b2c3d4-0002-4000-8000-000000000002", "mitre_ttp": "T1565.001"},
        {"stage": 3, "name": "Persistence via Redis Cache Backdoor", "target": "redis",
         "scenario_id": "a1b2c3d4-0005-4000-8000-000000000005", "mitre_ttp": "T1557"},
        {"stage": 4, "name": "Exfiltration via TimescaleDB Bulk Read", "target": "timescaledb",
         "scenario_id": "a1b2c3d4-0003-4000-8000-000000000003", "mitre_ttp": "T1499.002"},
    ]

    results = []
    chain_broken_at = None

    for stage in stages:
        logger.info(f"APT Chain Stage {stage['stage']}: {stage['name']}")
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(f"{CHAOS_ENGINE_URL}/experiments/start", json={
                    "scenario_id": stage["scenario_id"],
                    "name": f"APT Chain Stage {stage['stage']}: {stage['name']}",
                    "target_service": stage["target"],
                    "mitre_ttp": stage["mitre_ttp"],
                    "blast_radius": "medium",
                    "injection_type": "security",
                })
                result = resp.json()
                stage_result = {"stage": stage["stage"], "name": stage["name"],
                                "status": result.get("status", "unknown"),
                                "experiment_id": result.get("experiment_id", "")}
                results.append(stage_result)

                # Wait for experiment to complete
                await asyncio.sleep(30)

                # Check result — if defense caught it, chain is broken
                status_resp = await client.get(f"{CHAOS_ENGINE_URL}/experiments/status")
                exps = status_resp.json().get("experiments", {})
                exp = exps.get(result.get("experiment_id", ""), {})
                if exp.get("status") == "aborted":
                    chain_broken_at = stage["stage"]
                    stage_result["chain_broken"] = True
                    results[-1] = stage_result
                    break

        except Exception as e:
            logger.error(f"Stage {stage['stage']} failed: {e}")
            results.append({"stage": stage["stage"], "name": stage["name"], "status": "error", "error": str(e)})
            chain_broken_at = stage["stage"]
            break

    return {
        "attack_chain": "APT Simulation",
        "total_stages": len(stages),
        "stages_completed": len(results),
        "chain_broken_at_stage": chain_broken_at,
        "defense_held": chain_broken_at is not None,
        "results": results,
    }


# ═══ 5. Scenario Mutation Engine ═══
def mutate_scenarios(existing_scenarios: list) -> list:
    """Combine existing scenarios into new harder compound tests."""
    import random
    mutations = []
    if len(existing_scenarios) < 2:
        return []

    for _ in range(5):
        s1, s2 = random.sample(existing_scenarios, 2)
        mutation = {
            "scenario_id": str(uuid4()),
            "name": f"Mutation: {s1['name']} + {s2['name']}",
            "mitre_ttp": s1.get("mitre_ttp", ""),
            "attack_phase": s2.get("attack_phase", ""),
            "attack_vector": f"Combined: {s1.get('attack_vector', '')} THEN {s2.get('attack_vector', '')}",
            "target_service": s1.get("target_service", "api-gateway"),
            "injection_type": "security",
            "blast_radius": "high",
            "expected_behavior": f"System should defend against both {s1['name']} and {s2['name']} simultaneously",
            "success_criteria": "Both attack vectors detected and neutralized",
            "rollback_steps": list(set(s1.get("rollback_steps", []) + s2.get("rollback_steps", []))),
            "severity": "critical",
        }
        mutations.append(mutation)

    return mutations


# ═══ FastAPI ═══
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pg_pool
    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=5)
    except Exception as e:
        logger.error(f"DB connection failed: {e}")
    yield
    if pg_pool:
        await pg_pool.close()

app = FastAPI(title="Chaos AI Intelligence", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "chaos-ai-intelligence"}


@app.get("/gaps")
async def gaps():
    return await analyze_gaps()


@app.get("/predictions")
async def predictions():
    return await predict_weaknesses()


@app.get("/adaptive")
async def adaptive():
    return await get_adaptive_recommendations()


@app.post("/attack-chain")
async def attack_chain():
    return await simulate_attack_chain()


@app.post("/mutate")
async def mutate():
    try:
        with open("/app/scenarios.json") as f:
            scenarios = json.load(f)
    except Exception:
        scenarios = []
    mutations = mutate_scenarios(scenarios)
    return {"mutations": mutations, "count": len(mutations)}


@app.get("/metrics")
async def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    gap_data = await analyze_gaps()
    return PlainTextResponse(
        f'chaos_mitre_coverage_pct {gap_data["coverage_pct"]}\n'
        f'chaos_untested_ttps {gap_data["untested_ttps"]}\n',
        media_type="text/plain",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("CHAOS_AI_PORT", "8023")))
