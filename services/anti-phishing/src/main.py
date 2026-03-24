"""CyberShield-X Anti-Phishing Service — Main Entry Point."""

import base64
import os
import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app, Counter, Histogram
from pydantic import BaseModel

from .phishing_classifier import PhishingClassifier
from .url_analyzer import URLAnalyzer
from .voice_detector import VoiceDeepfakeDetector
from .psychographic_engine import PsychographicPredictor, UserProfile
from .url_detonator import URLDetonator
from .threat_intel_enricher import ThreatIntelEnricher
from .model_feedback_store import FeedbackStore
from .deepfake.image_detector import DeepfakeImageDetector

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("anti-phishing")

REQUEST_COUNT = Counter("aphishing_requests_total", "Total requests", ["endpoint"])
DETECT_COUNT  = Counter("aphishing_detections_total", "Total detections", ["label"])
LATENCY       = Histogram("aphishing_latency_seconds", "Request latency", ["endpoint"])

app = FastAPI(
    title="CyberShield-X Anti-Phishing Engine",
    version="1.0.0",
    description="AI-powered phishing detection, URL analysis, and deepfake voice detection",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())

# ── Singletons ──────────────────────────────────
classifier        = PhishingClassifier()
url_analyzer      = URLAnalyzer()
voice_detector    = VoiceDeepfakeDetector()
psych_predictor   = PsychographicPredictor()
url_detonator     = URLDetonator()
threat_enricher   = ThreatIntelEnricher()
feedback_store    = FeedbackStore()
image_detector    = DeepfakeImageDetector()

# ── In-memory detection stats ───────────────────
_stats = {
    "emails_analyzed": 0,
    "urls_analyzed": 0,
    "phishing_blocked": 0,
    "legit_passed": 0,
    # Phase 1
    "voice_analyzed": 0,
    "deepfakes_detected": 0,
    "psychographic_assessed": 0,
    "images_analyzed": 0,
    # Phase 2
    "detonations_run": 0,
    "iocs_enriched": 0,
    # Phase 3
    "feedback_submitted": 0,
}

# ── Model lifecycle state ────────────────────────
_model_meta: Dict[str, Any] = {
    "model_version": "1.0.0",
    "last_retrained": None,
    "pending_feedback_count": 0,
    "status": "active",
}

# ── Schemas ─────────────────────────────────────

class EmailAnalyzeRequest(BaseModel):
    text: str
    sender: Optional[str] = None
    subject: Optional[str] = None

class URLAnalyzeRequest(BaseModel):
    url: str

class BatchEmailRequest(BaseModel):
    texts: List[str]

# Phase 1 schemas
class VoiceAnalyzeRequest(BaseModel):
    """Base64-encoded raw PCM float32 audio bytes (mono, 16 kHz)."""
    audio_b64: str
    sample_rate: int = 16000

class ImageAnalyzeRequest(BaseModel):
    """Base64-encoded image bytes (JPEG / PNG)."""
    image_b64: str

class PsychographicRequest(BaseModel):
    user_id: str
    display_name: str
    department: str = ""
    role: str = ""
    seniority_level: int = 0
    financial_authority: bool = False
    public_exposure_score: float = 0.0
    email_open_rate: float = 0.5
    phishing_sim_fail_rate: float = 0.0
    past_incidents: int = 0
    access_level: int = 0
    travel_frequency: float = 0.0
    work_hours_variance: float = 0.0
    social_connections: int = 0

# Phase 2 schemas
class DetonateRequest(BaseModel):
    url: str
    timeout_ms: int = 30000

class EnrichRequest(BaseModel):
    ioc: str
    type: str = "url"    # url | ip | domain | hash

# Phase 3 schemas
class FeedbackRequest(BaseModel):
    text: str
    predicted_label: str
    correct_label: str

# ── Endpoints ────────────────────────────────────

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "anti-phishing",
        "version": "1.0.0",
        "stats": _stats,
    }

@app.post("/analyze/email")
async def analyze_email(req: EmailAnalyzeRequest):
    """Classify an email/message as phishing, spear-phishing, BEC, or legitimate."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_email").inc()

    full_text = f"Subject: {req.subject}\n\n{req.text}" if req.subject else req.text
    result = classifier.classify(full_text)

    _stats["emails_analyzed"] += 1
    if result.label != "legitimate":
        _stats["phishing_blocked"] += 1
    else:
        _stats["legit_passed"] += 1

    DETECT_COUNT.labels(label=result.label).inc()
    LATENCY.labels(endpoint="analyze_email").observe(time.time() - t0)

    return {
        "label": result.label,
        "confidence": round(result.confidence, 4),
        "probabilities": {k: round(v, 4) for k, v in result.probabilities.items()},
        "is_threat": result.label != "legitimate",
        "features_triggered": result.features_used,
        "sender": req.sender,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.post("/analyze/url")
async def analyze_url(req: URLAnalyzeRequest):
    """Analyze a URL for phishing indicators: homoglyphs, typosquatting, SSL, threat feeds."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_url").inc()

    result = await url_analyzer.analyze(req.url)

    _stats["urls_analyzed"] += 1
    if result.is_malicious:
        _stats["phishing_blocked"] += 1

    LATENCY.labels(endpoint="analyze_url").observe(time.time() - t0)

    return {
        "url": result.url,
        "risk_score": round(result.risk_score, 4),
        "is_malicious": result.is_malicious,
        "signals": result.signals,
        "homoglyph_detected": result.homoglyph_detected,
        "typosquat_target": result.typosquat_target,
        "threat_feed_hit": result.threat_feed_hit,
        "redirect_chain": result.redirect_chain,
        "cert_info": result.cert_info,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }

@app.post("/analyze/batch")
async def analyze_batch(req: BatchEmailRequest):
    """Batch classify multiple emails."""
    results = classifier.classify_batch(req.texts)
    _stats["emails_analyzed"] += len(results)
    return {
        "results": [
            {"label": r.label, "confidence": round(r.confidence, 4), "is_threat": r.label != "legitimate"}
            for r in results
        ],
        "total": len(results),
        "threats_found": sum(1 for r in results if r.label != "legitimate"),
    }

@app.get("/stats")
async def get_stats():
    _stats["pending_feedback_count"] = feedback_store.get_pending_count()
    return {"service": "anti-phishing", **_stats}


# ── Phase 1: Voice Deepfake Analysis ────────────

@app.post("/analyze/voice")
async def analyze_voice(req: VoiceAnalyzeRequest):
    """Detect AI-generated voice (vishing) from base64-encoded PCM audio."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_voice").inc()
    try:
        audio_bytes = base64.b64decode(req.audio_b64)
        audio_np = np.frombuffer(audio_bytes, dtype=np.float32)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid audio_b64: {e}")

    result = voice_detector.analyze(audio_np, req.sample_rate)
    _stats["voice_analyzed"] += 1
    if result.is_deepfake:
        _stats["deepfakes_detected"] += 1

    LATENCY.labels(endpoint="analyze_voice").observe(time.time() - t0)
    return {
        "is_deepfake": result.is_deepfake,
        "confidence": round(result.confidence, 4),
        "mfcc_anomaly_score": round(result.mfcc_anomaly_score, 4),
        "spectral_features": result.spectral_features,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }


# ── Phase 1: Image Deepfake Analysis ────────────

@app.post("/analyze/image")
async def analyze_image(req: ImageAnalyzeRequest):
    """Detect AI-generated / manipulated images."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_image").inc()
    try:
        image_bytes = base64.b64decode(req.image_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid image_b64: {e}")

    result = image_detector.analyze(image_bytes)
    _stats["images_analyzed"] += 1
    if result.is_deepfake:
        _stats["deepfakes_detected"] += 1

    LATENCY.labels(endpoint="analyze_image").observe(time.time() - t0)
    return {
        "is_deepfake": result.is_deepfake,
        "confidence": round(result.confidence, 4),
        "risk_score": result.risk_score,
        "signals": result.signals,
        "exif_anomalies": result.exif_anomalies,
        "noise_variance": result.noise_variance,
        "model_used": result.model_used,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }


# ── Phase 1: Psychographic Risk Prediction ───────

@app.post("/analyze/psychographic")
async def analyze_psychographic(req: PsychographicRequest):
    """Predict social-engineering targeting risk for a user profile."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="analyze_psychographic").inc()

    profile = UserProfile(
        user_id=req.user_id,
        display_name=req.display_name,
        department=req.department,
        role=req.role,
        seniority_level=req.seniority_level,
        financial_authority=req.financial_authority,
        public_exposure_score=req.public_exposure_score,
        email_open_rate=req.email_open_rate,
        phishing_sim_fail_rate=req.phishing_sim_fail_rate,
        past_incidents=req.past_incidents,
        access_level=req.access_level,
        travel_frequency=req.travel_frequency,
        work_hours_variance=req.work_hours_variance,
        social_connections=req.social_connections,
    )
    result = psych_predictor.predict(profile)
    _stats["psychographic_assessed"] += 1

    LATENCY.labels(endpoint="analyze_psychographic").observe(time.time() - t0)
    return {
        "user_id": result.user_id,
        "risk_tier": result.risk_tier,
        "risk_score": result.risk_score,
        "attack_vectors": result.attack_vectors,
        "contributing_factors": result.contributing_factors,
        "recommended_interventions": result.recommended_interventions,
        "predicted_at": result.predicted_at,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }


# ── Phase 2: Sandbox URL Detonation ─────────────

@app.post("/analyze/detonate")
async def detonate_url(req: DetonateRequest):
    """Detonate a URL in a sandboxed headless browser and return behaviour report."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="detonate").inc()

    result = await url_detonator.detonate(req.url, timeout_ms=req.timeout_ms)
    _stats["detonations_run"] += 1
    if result.verdict == "malicious":
        _stats["phishing_blocked"] += 1

    LATENCY.labels(endpoint="detonate").observe(time.time() - t0)
    return {
        "url": result.url,
        "final_url": result.final_url,
        "verdict": result.verdict,
        "risk_score": round(result.risk_score, 4),
        "credential_forms_detected": len(result.credential_forms),
        "credential_forms": result.credential_forms,
        "network_requests_count": len(result.network_requests),
        "javascript_alerts": result.javascript_alerts,
        "screenshot_path": result.screenshot_path,
        "detonation_time_ms": result.detonation_time_ms,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }


# ── Phase 2: Threat Intel Enrichment ────────────

@app.post("/intel/enrich")
async def enrich_ioc(req: EnrichRequest):
    """Enrich an IOC (URL, IP, domain, file hash) with threat intel from multiple sources."""
    t0 = time.time()
    REQUEST_COUNT.labels(endpoint="intel_enrich").inc()

    result = await threat_enricher.enrich(req.ioc, req.type)
    _stats["iocs_enriched"] += 1

    LATENCY.labels(endpoint="intel_enrich").observe(time.time() - t0)
    return {
        "ioc": result.ioc,
        "ioc_type": result.ioc_type,
        "reputation_score": result.reputation_score,
        "is_malicious": result.reputation_score >= 0.5,
        "sources_hit": result.sources_hit,
        "tags": result.tags,
        "last_seen": result.last_seen,
        "enriched_at": result.enriched_at,
        "latency_ms": round((time.time() - t0) * 1000, 2),
    }


# ── Phase 3: Analyst Feedback ────────────────────

@app.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    """
    Submit analyst correction on a model prediction.
    Corrections feed the retraining pipeline.
    """
    REQUEST_COUNT.labels(endpoint="feedback").inc()
    pending = feedback_store.append(
        text=req.text,
        predicted_label=req.predicted_label,
        correct_label=req.correct_label,
    )
    _stats["feedback_submitted"] += 1
    _model_meta["pending_feedback_count"] = pending
    return {
        "status": "accepted",
        "predicted_label": req.predicted_label,
        "correct_label": req.correct_label,
        "pending_feedback_count": pending,
    }


# ── Phase 3: Model Status ────────────────────────

@app.get("/model/status")
async def model_status():
    """Return current phishing model version, last retrain time, and pending feedback queue."""
    _model_meta["pending_feedback_count"] = feedback_store.get_pending_count()
    return {
        "service": "anti-phishing",
        **_model_meta,
    }

@app.on_event("startup")
async def startup_event():
    logger.info("Anti-Phishing Engine starting up — loading classifier...")
    classifier.load_model()
    voice_detector.load_model()
    image_detector.load_model()
    logger.info(
        "Anti-Phishing Engine ready. Classifier=%s VoiceModel=%s ImageModel=%s",
        classifier._loaded, voice_detector._loaded, image_detector._loaded,
    )
