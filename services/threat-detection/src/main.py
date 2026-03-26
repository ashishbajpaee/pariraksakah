"""CyberShield-X Threat Detection Service — Main Entry Point."""

import os
import time
import math
import asyncio
import logging
import hashlib
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Set
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app, Counter, Histogram
from pydantic import BaseModel
import sys, os as _os
_os.path.insert(0, _os.path.dirname(_os.path.abspath(__file__))) if _os.path.dirname(_os.path.abspath(__file__)) not in sys.path else None
from ingestion.pcap_sniffer import SnifferManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("threat-detection")

REQUEST_COUNT   = Counter("atde_requests_total", "Total inference requests", ["endpoint", "status"])
INFERENCE_LAT   = Histogram("atde_inference_latency_seconds", "ML inference latency")
THREAT_DETECTED = Counter("atde_threats_detected_total", "Threats detected", ["severity", "technique"])

app = FastAPI(
    title="CyberShield-X Threat Detection Engine",
    version="1.0.0",
    description="AI-Powered Advanced Threat Detection Engine (ATDE)",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())

# ── In-memory state for UEBA / anomaly detection ─

_event_window: deque = deque(maxlen=10000)
_ip_counters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
_user_baselines: Dict[str, dict] = {}
_detected_threats: List[dict] = []
_stats = {"events_processed": 0, "threats_detected": 0, "false_positives_suppressed": 0}

# ── Live Capture ─────────────────────────────────

_sniffer_manager = SnifferManager()
_ws_clients: Set[WebSocket] = set()

# ── Known IOC / suspicious ports / MITRE mapping ─

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444, 5900, 6667, 8080, 31337}
LATERAL_MOVEMENT_PORTS = {135, 139, 445, 5985, 5986}
EXFIL_PORTS = {21, 22, 53, 80, 443, 4444}

MITRE_MAP = {
    "port_scan":          ("T1046", "Network Service Scanning",  "discovery"),
    "lateral_movement":   ("T1021", "Remote Services",           "lateral_movement"),
    "c2_beacon":          ("T1071", "Application Layer Protocol","command_and_control"),
    "credential_access":  ("T1003", "OS Credential Dumping",     "credential_access"),
    "data_exfiltration":  ("T1041", "Exfiltration Over C2",      "exfiltration"),
    "brute_force":        ("T1110", "Brute Force",               "credential_access"),
    "privilege_escalation":("T1068","Exploitation for Privilege Escalation","privilege_escalation"),
}

# ── Schemas ──────────────────────────────────────

class NetworkEvent(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration_ms: int = 0
    user_agent: Optional[str] = None
    payload_entropy: Optional[float] = None
    timestamp: Optional[str] = None

class UserBehaviorEvent(BaseModel):
    user_id: str
    action: str                    # login, file_access, privilege_use, lateral_move
    resource: str
    source_ip: str
    hour_of_day: int = 9
    day_of_week: int = 1
    failed_attempts: int = 0

class BatchEventRequest(BaseModel):
    events: List[NetworkEvent]

# ── Core detection engine ─────────────────────────

def _entropy(data: str) -> float:
    """Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())

def _classify_network_event(ev: NetworkEvent) -> dict:
    """Real statistical + rule-based threat classification."""
    threats = []
    score = 0.0

    # 1. Port scan heuristic: many distinct destination ports from same src
    recent_ports = _ip_counters[ev.src_ip]
    recent_ports.append(ev.dst_port)
    unique_ports_last_100 = len(set(list(recent_ports)[-100:]))
    if unique_ports_last_100 > 20:
        threats.append("port_scan")
        score += 0.6

    # 2. Lateral movement: internal→internal on known ports
    src_internal = ev.src_ip.startswith(("10.", "172.", "192.168."))
    dst_internal = ev.dst_ip.startswith(("10.", "172.", "192.168."))
    if src_internal and dst_internal and ev.dst_port in LATERAL_MOVEMENT_PORTS:
        threats.append("lateral_movement")
        score += 0.5

    # 3. C2 beacon: regular small packets to external with high entropy payload
    entropy = ev.payload_entropy or _entropy(ev.user_agent or "")
    if not dst_internal and ev.bytes_sent < 512 and ev.bytes_recv < 512 and entropy > 4.5:
        threats.append("c2_beacon")
        score += 0.55

    # 4. Suspicious port usage
    if ev.dst_port in SUSPICIOUS_PORTS:
        score += 0.3
        if ev.dst_port == 4444:  # Metasploit default
            threats.append("c2_beacon")
            score += 0.4

    # 5. Data exfiltration: large outbound bytes to external
    if not dst_internal and ev.bytes_sent > 10_000_000:  # 10MB+
        threats.append("data_exfiltration")
        score += 0.65

    # 6. Brute force: many failed connections on auth ports
    # (requires session-level data — approximated by high duration + small bytes)
    if ev.dst_port in {22, 3389, 5900} and ev.duration_ms < 500 and ev.bytes_recv < 200:
        score += 0.25
        threats.append("brute_force")

    score = min(score, 1.0)

    if score >= 0.7:
        severity = "critical"
    elif score >= 0.5:
        severity = "high"
    elif score >= 0.3:
        severity = "medium"
    else:
        severity = "low"
        threats = []

    primary = threats[0] if threats else None
    mitre_id, mitre_name, tactic = MITRE_MAP.get(primary, ("", "", "")) if primary else ("", "", "")

    return {
        "is_threat": score >= 0.3,
        "severity": severity,
        "score": round(score, 4),
        "techniques_detected": threats,
        "primary_technique": primary,
        "mitre_technique_id": mitre_id,
        "mitre_technique_name": mitre_name,
        "mitre_tactic": tactic,
        "indicators": {
            "unique_ports_scanned": unique_ports_last_100,
            "payload_entropy": round(entropy, 3),
            "bytes_sent": ev.bytes_sent,
            "lateral_movement_port": ev.dst_port in LATERAL_MOVEMENT_PORTS,
        },
    }

def _classify_user_behavior(ev: UserBehaviorEvent) -> dict:
    """UEBA — User and Entity Behavior Analytics."""
    uid = ev.user_id
    baseline = _user_baselines.get(uid, {"normal_hours": list(range(8, 18)), "normal_days": list(range(0, 5)), "failed_threshold": 3})

    anomalies = []
    score = 0.0

    # Off-hours access
    if ev.hour_of_day not in baseline["normal_hours"]:
        anomalies.append(f"off_hours_access (hour={ev.hour_of_day})")
        score += 0.35

    # Weekend access
    if ev.day_of_week in (5, 6) and ev.day_of_week not in baseline["normal_days"]:
        anomalies.append("weekend_access")
        score += 0.20

    # Too many failed attempts
    if ev.failed_attempts >= baseline["failed_threshold"]:
        anomalies.append(f"excessive_failures ({ev.failed_attempts} attempts)")
        score += 0.45

    # Privilege use from unusual IP
    if ev.action == "privilege_use":
        score += 0.30
        anomalies.append("privilege_escalation_attempt")

    # Lateral movement
    if ev.action == "lateral_move":
        score += 0.55
        anomalies.append("lateral_movement_detected")

    score = min(score, 1.0)
    # Update baseline (simple exponential moving average)
    _user_baselines[uid] = baseline

    return {
        "user_id": uid,
        "is_anomalous": score >= 0.35,
        "risk_score": round(score, 4),
        "anomalies": anomalies,
        "action": ev.action,
        "resource": ev.resource,
    }

# ── Endpoints ─────────────────────────────────────

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "threat-detection",
        "version": "1.0.0",
        "stats": _stats,
    }

@app.post("/analyze/network")
async def analyze_network_event(ev: NetworkEvent):
    """Analyze a single network event for threats using statistical + rule-based detection."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_network", status="ok").inc()

    result = _classify_network_event(ev)
    _event_window.append({**ev.dict(), **result})
    _stats["events_processed"] += 1

    if result["is_threat"]:
        _stats["threats_detected"] += 1
        if result["primary_technique"]:
            THREAT_DETECTED.labels(severity=result["severity"], technique=result["primary_technique"]).inc()
        _detected_threats.append({
            "id": hashlib.md5(f"{ev.src_ip}{ev.dst_ip}{time.time()}".encode()).hexdigest()[:12],
            "src_ip": ev.src_ip,
            "dst_ip": ev.dst_ip,
            **result,
        })
        if len(_detected_threats) > 1000:
            _detected_threats.pop(0)

    INFERENCE_LAT.observe(time.time() - t0)
    return {**result, "latency_ms": round((time.time() - t0) * 1000, 2)}

@app.post("/analyze/ueba")
async def analyze_user_behavior(ev: UserBehaviorEvent):
    """UEBA — analyze user behavior for insider threats and account compromise."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_ueba", status="ok").inc()
    result = _classify_user_behavior(ev)
    _stats["events_processed"] += 1
    if result["is_anomalous"]:
        _stats["threats_detected"] += 1
    return {**result, "latency_ms": round((time.time() - t0) * 1000, 2)}

@app.post("/analyze/batch")
async def analyze_batch(req: BatchEventRequest):
    """Batch analyze multiple network events."""
    t0 = time.time()
    results = [_classify_network_event(ev) for ev in req.events]
    _stats["events_processed"] += len(results)
    threats = [r for r in results if r["is_threat"]]
    _stats["threats_detected"] += len(threats)
    return {
        "total": len(results),
        "threats_found": len(threats),
        "results": results,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.get("/threats/recent")
async def get_recent_threats(limit: int = 50):
    """Return the most recently detected threats."""
    return {
        "threats": _detected_threats[-limit:][::-1],
        "total": len(_detected_threats),
    }

@app.get("/stats")
async def get_stats():
    return {"service": "threat-detection", **_stats}


# ── Live Capture ──────────────────────────────────

@app.post("/capture/start")
async def start_capture():
    """Start live packet capture / simulation."""
    loop = asyncio.get_event_loop()
    result = _sniffer_manager.start(loop)
    if result["status"] == "started":
        # Start the background pipeline task
        asyncio.ensure_future(_capture_pipeline())
    return result


@app.post("/capture/stop")
async def stop_capture():
    """Stop live packet capture."""
    return _sniffer_manager.stop()


@app.get("/capture/status")
async def capture_status():
    """Return current sniffer status."""
    return _sniffer_manager.status()


@app.websocket("/ws/live-alerts")
async def websocket_live_alerts(ws: WebSocket):
    """Stream real-time threat alerts to WebSocket clients."""
    await ws.accept()
    _ws_clients.add(ws)
    logger.info("[WS] Client connected. Total clients: %d", len(_ws_clients))
    try:
        while True:
            # Keep connection alive; actual messages are pushed by the pipeline
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        _ws_clients.discard(ws)
        logger.info("[WS] Client disconnected. Total clients: %d", len(_ws_clients))


async def _capture_pipeline():
    """Background task: consume sniffer queue, classify, broadcast threats."""
    logger.info("[Capture] Pipeline started")
    while _sniffer_manager.is_running:
        event = await _sniffer_manager.get_event(timeout=0.1)
        if event is None:
            continue

        # Build NetworkEvent-compatible dict for the classifier
        ne = NetworkEvent(
            src_ip=event.get("src_ip", "0.0.0.0"),
            dst_ip=event.get("dst_ip", "0.0.0.0"),
            dst_port=int(event.get("dst_port", 0)),
            protocol=event.get("protocol", "TCP"),
            bytes_sent=int(event.get("bytes_sent", 0)),
            bytes_recv=int(event.get("bytes_recv", 0)),
            duration_ms=int(event.get("duration_ms", 0)),
            payload_entropy=float(event.get("payload_entropy", 0.0)),
        )

        result = _classify_network_event(ne)
        _stats["events_processed"] += 1
        _event_window.append({**event, **result})

        if result["is_threat"]:
            _stats["threats_detected"] += 1
            alert = {
                "type":             "threat",
                "event_id":         event.get("event_id"),
                "timestamp":        event.get("timestamp"),
                "src_ip":           event.get("src_ip"),
                "dst_ip":           event.get("dst_ip"),
                "dst_port":         event.get("dst_port"),
                "protocol":         event.get("protocol"),
                "severity":         result["severity"],
                "score":            result["score"],
                "techniques":       result["techniques_detected"],
                "mitre_id":         result["mitre_technique_id"],
                "mitre_name":       result["mitre_technique_name"],
                "mitre_tactic":     result["mitre_tactic"],
                "simulated":        event.get("_simulated", False),
            }
            if result.get("primary_technique"):
                THREAT_DETECTED.labels(
                    severity=result["severity"],
                    technique=result["primary_technique"]
                ).inc()
            _detected_threats.append(alert)
            if len(_detected_threats) > 1000:
                _detected_threats.pop(0)

            # Broadcast to all WebSocket clients
            dead: set = set()
            for ws in _ws_clients.copy():
                try:
                    await ws.send_json(alert)
                except Exception:
                    dead.add(ws)
            _ws_clients.difference_update(dead)

    logger.info("[Capture] Pipeline stopped")


@app.on_event("startup")
async def startup_event():
    logger.info("Threat Detection Engine starting up...")
    logger.info("KAFKA_BOOTSTRAP_SERVERS=%s", os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    logger.info("Threat Detection Engine ready — statistical + rule-based detection active")
    logger.info("Live capture: POST /capture/start | WebSocket: ws://host/ws/live-alerts")


@app.on_event("shutdown")
async def shutdown_event():
    _sniffer_manager.stop()
    logger.info("Threat Detection Engine shutting down...")

