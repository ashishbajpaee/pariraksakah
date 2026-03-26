import os, json, time, logging
from datetime import datetime
from threading import Thread
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NET-MON] %(message)s")

PEER_URL: str = os.getenv("PEER_NODE_URL", "http://dsrn-peer-node:8060")
CONSENSUS_URL: str = os.getenv("CONSENSUS_ENGINE_URL", "http://dsrn-consensus-engine:8061")
TRUST_URL: str = os.getenv("TRUST_MANAGER_URL", "http://dsrn-peer-trust-manager:8064")
LEDGER_URL: str = os.getenv("LEDGER_URL", "http://dsrn-blockchain-ledger:8065")

health_history: List[Dict[str, Any]] = []
alerts: List[Dict[str, str]] = []

def fetch_json(url: str, default: Any = None) -> Any:
    try:
        import requests
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return default or {}

def calculate_resilience() -> Dict[str, Any]:
    peers_data = fetch_json(f"{PEER_URL}/peer/list", {"peers": []})
    peer_list = peers_data.get("peers", [])
    active = [p for p in peer_list if isinstance(p, dict) and p.get("status") == "ACTIVE"]
    peer_count: int = len(active)

    consensus_data = fetch_json(f"{CONSENSUS_URL}/consensus/history", {"rounds": []})
    round_list = consensus_data.get("rounds", [])
    committed = sum(1 for r in round_list if isinstance(r, dict) and r.get("result") == "COMMITTED")
    total_rounds = max(len(round_list), 1)
    success_rate: float = float(committed) / float(total_rounds)

    trust_data = fetch_json(f"{TRUST_URL}/trust/network/health", {})
    trust_avg: float = float(trust_data.get("average_reputation", 75))
    above_thresh: int = int(trust_data.get("peers_above_threshold", 0))

    peer_adequacy: float = min(peer_count / 4.0, 1.0) * 25.0
    consensus_health: float = success_rate * 25.0
    intel_quality: float = 0.85 * 25.0
    trust_dist: float = (float(above_thresh) / float(max(peer_count, 1))) * 25.0

    raw_score: float = peer_adequacy + consensus_health + intel_quality + trust_dist
    score: float = round(raw_score, 1)

    return {
        "resilience_score": min(score, 100.0),
        "peer_count": peer_count,
        "byzantine_tolerance": max((peer_count - 1) // 3, 0),
        "consensus_success_rate": round(success_rate * 100.0, 1),
        "trust_average": round(trust_avg, 1),
        "timestamp": datetime.utcnow().isoformat(),
    }

def monitor_loop() -> None:
    import redis as redis_mod
    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PASS: str = os.getenv("REDIS_PASSWORD", "changeme_redis")
    rds = redis_mod.Redis(host=REDIS_HOST, port=6379, password=REDIS_PASS, decode_responses=True)

    while True:
        try:
            metrics = calculate_resilience()
            health_history.append(metrics)
            if len(health_history) > 1000:
                health_history.pop(0)
            rds.setex("dsrn:network:resilience", 60, json.dumps(metrics))

            pc = metrics.get("peer_count", 0)
            rs = metrics.get("resilience_score", 0)
            if isinstance(pc, int) and pc < 4:
                alerts.append({"type": "LOW_PEER_COUNT", "severity": "HIGH", "message": f"Only {pc} peers", "at": str(metrics.get("timestamp", ""))})
            if isinstance(rs, (int, float)) and rs < 50:
                alerts.append({"type": "LOW_RESILIENCE", "severity": "CRITICAL", "message": f"Score={rs}", "at": str(metrics.get("timestamp", ""))})
        except Exception as e:
            logging.error(f"Monitor error: {e}")
        time.sleep(30)

try:
    from fastapi import FastAPI
    app = FastAPI(title="DSRN Network Health Monitor")

    @app.on_event("startup")
    def startup() -> None:
        Thread(target=monitor_loop, daemon=True).start()

    @app.get("/network/health")
    async def health() -> Any:
        import redis as redis_mod
        REDIS_HOST = os.getenv("REDIS_HOST", "redis")
        REDIS_PASS = os.getenv("REDIS_PASSWORD", "changeme_redis")
        rds = redis_mod.Redis(host=REDIS_HOST, port=6379, password=REDIS_PASS, decode_responses=True)
        cached = rds.get("dsrn:network:resilience")
        if cached:
            return json.loads(str(cached))
        return calculate_resilience()

    @app.get("/network/topology")
    async def topology() -> Any:
        return fetch_json(f"{PEER_URL}/peer/network/topology", {})

    @app.get("/network/metrics")
    async def metrics_endpoint() -> Any:
        return {"history_length": len(health_history), "latest": health_history[-1] if health_history else {}}

    @app.get("/network/alerts")
    async def get_alerts() -> Any:
        return {"alerts": list(alerts[-50:])}

    @app.get("/network/resilience")
    async def resilience() -> Any:
        return calculate_resilience()

    @app.get("/metrics")
    async def prom_metrics() -> str:
        latest = health_history[-1] if health_history else {}
        return f"dsrn_network_resilience_score {latest.get('resilience_score', 0)}\ndsrn_network_peer_count {latest.get('peer_count', 0)}\n"

except ImportError:
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("MONITOR_PORT", "8066")))
