import os, json, time, logging
import numpy as np
from datetime import datetime
from threading import Thread
from fastapi import FastAPI
from pydantic import BaseModel
from confluent_kafka import Producer
import redis
import requests
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRUST-MGR] %(message)s")

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PASS = os.getenv("REDIS_PASSWORD", "changeme_redis")
CONSENSUS_URL = os.getenv("CONSENSUS_ENGINE_URL", "http://dsrn-consensus-engine:8061")

app = FastAPI(title="DSRN Peer Trust & Reputation Manager")
producer = Producer({"bootstrap.servers": KAFKA_BROKER})
rds = redis.Redis(host=REDIS_HOST, port=6379, password=REDIS_PASS, decode_responses=True)

# In-memory peer reputation store
peer_scores = {
    "local-node": {"reputation": 100, "trust": 100, "intel_quality": 1.0, "participation": 1.0, "false_positive_rate": 0.0},
    "sim-peer-1": {"reputation": 85, "trust": 90, "intel_quality": 0.9, "participation": 0.85, "false_positive_rate": 0.05},
    "sim-peer-2": {"reputation": 80, "trust": 85, "intel_quality": 0.85, "participation": 0.8, "false_positive_rate": 0.08},
    "sim-peer-3": {"reputation": 92, "trust": 95, "intel_quality": 0.95, "participation": 0.92, "false_positive_rate": 0.02},
    "sim-peer-4": {"reputation": 40, "trust": 35, "intel_quality": 0.3, "participation": 0.2, "false_positive_rate": 0.45},
}

blacklist = []
anomaly_model = None

def publish(topic, payload):
    producer.produce(topic, key="trust", value=json.dumps(payload))
    producer.flush()

def calculate_reputation(peer_id):
    s = peer_scores.get(peer_id, {})
    iq = s.get("intel_quality", 0.5) * 30
    rp = s.get("participation", 0.5) * 20
    fp = (1.0 - s.get("false_positive_rate", 0.5)) * 20
    nc = 0.8 * 15  # network contribution placeholder
    ii = 0.9 * 15  # identity integrity placeholder
    return min(round(iq + rp + fp + nc + ii, 1), 100)

def train_anomaly_model():
    global anomaly_model
    logging.info("Training Byzantine peer detection model...")
    normal = np.random.normal(loc=[0.85, 0.8, 0.05, 0.9, 0.9], scale=[0.1, 0.15, 0.03, 0.1, 0.1], size=(500, 5))
    anomaly_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    anomaly_model.fit(normal)

def detect_byzantine(peer_id):
    if anomaly_model is None:
        return False
    s = peer_scores.get(peer_id, {})
    features = np.array([[s.get("intel_quality", 0.5), s.get("participation", 0.5),
                          s.get("false_positive_rate", 0.5), 0.8, 0.8]])
    pred = anomaly_model.predict(features)[0]
    return pred == -1

def reputation_loop():
    while True:
        time.sleep(30)
        for pid in list(peer_scores.keys()):
            new_score = calculate_reputation(pid)
            peer_scores[pid]["reputation"] = new_score
            rds.setex(f"dsrn:trust:{pid}", 300, new_score)
            if detect_byzantine(pid):
                logging.warning(f"Byzantine behavior detected: {pid}")
                peer_scores[pid]["reputation"] = 0
                blacklist.append(pid)
                publish("dsrn.anomaly.peer", {"peer_id": pid, "reason": "Byzantine behavior", "detected_at": datetime.utcnow().isoformat()})
                try:
                    requests.post(f"{CONSENSUS_URL}/consensus/propose", json={
                        "proposal_type": "PEER_EJECTION", "proposal_hash": pid, "participants": []
                    }, timeout=3)
                except: pass

@app.on_event("startup")
def startup():
    train_anomaly_model()
    Thread(target=reputation_loop, daemon=True).start()

@app.get("/trust/peer/{peer_id}")
async def get_peer_trust(peer_id: str):
    s = peer_scores.get(peer_id, {})
    return {"peer_id": peer_id, "reputation_score": s.get("reputation", 0), "trust_score": s.get("trust", 0),
            "intel_quality": s.get("intel_quality", 0), "participation": s.get("participation", 0)}

@app.get("/trust/leaderboard")
async def leaderboard():
    ranked = sorted(peer_scores.items(), key=lambda x: x[1].get("reputation", 0), reverse=True)
    return {"leaderboard": [{"peer_id": p, **s} for p, s in ranked]}

@app.get("/trust/blacklist")
async def get_blacklist():
    return {"blacklisted_peers": blacklist}

@app.post("/trust/report/{peer_id}")
async def report_peer(peer_id: str):
    if peer_id in peer_scores:
        peer_scores[peer_id]["reputation"] = max(0, peer_scores[peer_id]["reputation"] - 20)
        return {"status": "reported", "new_reputation": peer_scores[peer_id]["reputation"]}
    return {"error": "Peer not found"}

@app.get("/trust/network/health")
async def network_health():
    avg = np.mean([s.get("reputation", 0) for s in peer_scores.values()])
    above_75 = sum(1 for s in peer_scores.values() if s.get("reputation", 0) >= 75)
    return {"average_reputation": round(float(avg), 1), "peers_above_threshold": above_75,
            "total_peers": len(peer_scores), "blacklisted": len(blacklist)}

@app.get("/metrics")
async def metrics():
    return f"dsrn_peer_trust_avg {np.mean([s.get('reputation',0) for s in peer_scores.values()]):.1f}\n"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("TRUST_MANAGER_PORT", "8064")))
