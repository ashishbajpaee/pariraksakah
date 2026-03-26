import os, json, time, random, hashlib, logging, re
from datetime import datetime
from threading import Thread
from typing import Dict, List, Optional
from fastapi import FastAPI
from pydantic import BaseModel
from confluent_kafka import Producer
import redis
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [GOSSIP] %(message)s")

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_URL = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS = os.getenv("REDIS_PASSWORD", "changeme_redis")
CONSENSUS_URL = os.getenv("CONSENSUS_ENGINE_URL", "http://dsrn-consensus-engine:8061")
PEER_NODE_URL = os.getenv("PEER_NODE_URL", "http://dsrn-peer-node:8060")

GOSSIP_FANOUT = int(os.getenv("GOSSIP_FANOUT", "3"))
GOSSIP_INTERVAL = int(os.getenv("GOSSIP_INTERVAL_SECS", "15"))
MAX_HOPS = int(os.getenv("GOSSIP_MAX_HOPS", "10"))
MAX_AGE_HOURS = 24

app = FastAPI(title="DSRN Threat Intelligence Gossip Protocol")
producer = Producer({"bootstrap.servers": KAFKA_BROKER})
rds = redis.Redis(host=REDIS_URL, port=REDIS_PORT, password=REDIS_PASS, decode_responses=True)

received_intel: List[Dict] = []
validated_intel: List[Dict] = []

class ThreatIntel(BaseModel):
    threat_id: str = ""
    threat_type: str
    severity: str
    indicators: dict
    mitre_ttp: str = ""
    confidence_score: float = 0.8
    source_peer_id: str = ""
    hop_count: int = 0

def publish(topic, payload):
    try:
        producer.produce(topic, key="gossip", value=json.dumps(payload))
        producer.flush()
    except Exception as e:
        logging.error(f"Kafka publish error: {e}")

def anonymize_intel(intel: dict) -> dict:
    """Privacy-preserving transformations before external sharing"""
    anon = intel.copy()
    indicators = anon.get("indicators", {})
    # IP anonymization - replace with /24 ranges
    if "ip" in indicators:
        ip = indicators["ip"]
        parts = ip.split(".")
        if len(parts) == 4:
            indicators["ip"] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    # Service anonymization
    if "service" in indicators:
        indicators["service"] = "generic-web-service"
    # Hostname hashing
    if "hostname" in indicators:
        indicators["hostname"] = hashlib.sha256(indicators["hostname"].encode()).hexdigest()[:12]
    anon["indicators"] = indicators
    return anon

def is_seen(threat_id: str) -> bool:
    return rds.sismember("dsrn:gossip:bloom", threat_id)

def mark_seen(threat_id: str):
    rds.sadd("dsrn:gossip:bloom", threat_id)
    rds.expire("dsrn:gossip:bloom", MAX_AGE_HOURS * 3600)

def gossip_loop():
    """Background epidemic gossip propagation"""
    while True:
        time.sleep(GOSSIP_INTERVAL)
        try:
            peers_resp = requests.get(f"{PEER_NODE_URL}/peer/list", timeout=3)
            if peers_resp.status_code != 200:
                continue
            peers = peers_resp.json().get("peers", [])
            active = [p for p in peers if p.get("status") == "ACTIVE"]
            if not active:
                continue
            # Select random subset
            targets = random.sample(active, min(GOSSIP_FANOUT, len(active)))
            # Share recent unshared intel
            for intel in received_intel[-20:]:
                if intel.get("hop_count", 0) >= MAX_HOPS:
                    continue
                anon = anonymize_intel(intel)
                anon["hop_count"] = anon.get("hop_count", 0) + 1
                for peer in targets:
                    publish("dsrn.threat.broadcast", {**anon, "target_peer": peer["peer_id"]})
        except Exception as e:
            logging.error(f"Gossip loop error: {e}")

@app.on_event("startup")
def startup():
    Thread(target=gossip_loop, daemon=True).start()
    logging.info("Gossip protocol started")

@app.post("/threat/share")
async def share_threat(intel: ThreatIntel):
    tid = intel.threat_id or f"threat-{hashlib.sha256(json.dumps(intel.indicators).encode()).hexdigest()[:12]}"
    intel_dict = intel.dict()
    intel_dict["threat_id"] = tid
    intel_dict["source_peer_id"] = intel.source_peer_id or "local-node"
    intel_dict["shared_at"] = datetime.utcnow().isoformat()

    if is_seen(tid):
        return {"status": "duplicate", "threat_id": tid}

    mark_seen(tid)
    anon = anonymize_intel(intel_dict)
    received_intel.append(intel_dict)
    publish("dsrn.threat.broadcast", anon)

    # Submit to consensus if high confidence
    if intel.confidence_score >= 0.8:
        try:
            requests.post(f"{CONSENSUS_URL}/consensus/propose", json={
                "proposal_type": "THREAT_VALIDATION",
                "proposal_hash": hashlib.sha256(tid.encode()).hexdigest(),
                "participants": []
            }, timeout=3)
        except:
            pass
    validated_intel.append({**intel_dict, "consensus_reached": intel.confidence_score >= 0.8})
    publish("dsrn.threat.validated", intel_dict)
    return {"status": "shared", "threat_id": tid, "anonymized": True}

@app.get("/threat/received")
async def get_received(limit: int = 50):
    return {"total": len(received_intel), "threats": received_intel[-limit:]}

@app.get("/threat/validated")
async def get_validated(limit: int = 50):
    return {"total": len(validated_intel), "threats": validated_intel[-limit:]}

@app.get("/threat/network/stats")
async def gossip_stats():
    bloom_size = rds.scard("dsrn:gossip:bloom") or 0
    return {"received_total": len(received_intel), "validated_total": len(validated_intel),
            "bloom_filter_size": bloom_size, "gossip_fanout": GOSSIP_FANOUT,
            "gossip_interval_secs": GOSSIP_INTERVAL, "max_hops": MAX_HOPS}

@app.get("/metrics")
async def metrics():
    return f"dsrn_gossip_received_total {len(received_intel)}\ndsrn_gossip_validated_total {len(validated_intel)}\n"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("GOSSIP_PORT", "8062")))
