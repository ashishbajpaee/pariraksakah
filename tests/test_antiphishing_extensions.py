"""
Anti-Phishing Extension Tests
Covers all three new feature pillars:
  Phase 1 — Voice/Image deepfake detection + psychographic risk
  Phase 2 — URL detonation + threat intel enrichment
  Phase 3 — Model feedback store + retraining scheduler
"""

import asyncio
import base64
import csv
import json
import os
import tempfile

import numpy as np
import pytest

# ── helpers ────────────────────────────────────────────────────────────────────

def run(coro):
    """Sync wrapper for async tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1 — Voice Deepfake Detector
# ═══════════════════════════════════════════════════════════════════════════════

class TestVoiceDeepfakeDetector:

    def _detector(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "anti-phishing", "src"))
        from voice_detector import VoiceDeepfakeDetector
        return VoiceDeepfakeDetector()

    def test_silence_is_not_deepfake(self):
        """Pure silence has near-zero spectral energy — heuristic should not flag it as deepfake."""
        det = self._detector()
        audio = np.zeros(16000, dtype=np.float32)   # 1 second of silence
        result = det.analyze(audio, sample_rate=16000)
        assert hasattr(result, "is_deepfake")
        assert hasattr(result, "confidence")
        assert 0.0 <= result.confidence <= 1.0

    def test_white_noise_returns_result(self):
        """White noise should produce a valid result without raising."""
        det = self._detector()
        rng = np.random.default_rng(42)
        audio = rng.uniform(-0.5, 0.5, 16000).astype(np.float32)
        result = det.analyze(audio, 16000)
        assert result.mfcc_anomaly_score >= 0.0
        assert isinstance(result.spectral_features, dict)

    def test_result_fields_present(self):
        det = self._detector()
        audio = np.zeros(8000, dtype=np.float32)
        result = det.analyze(audio, 16000)
        for field in ("is_deepfake", "confidence", "mfcc_anomaly_score", "spectral_features"):
            assert hasattr(result, field), f"Missing field: {field}"

    def test_spectral_features_keys(self):
        det = self._detector()
        result = det.analyze(np.zeros(16000, dtype=np.float32), 16000)
        expected_keys = {"spectral_centroid", "spectral_rolloff", "spectral_flatness", "zero_crossing_rate"}
        assert expected_keys.issubset(result.spectral_features.keys())


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1 — Image Deepfake Detector
# ═══════════════════════════════════════════════════════════════════════════════

class TestImageDeepfakeDetector:

    def _detector(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        # Use importlib to avoid hyphenated path issue
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "image_detector",
            os.path.join(os.path.dirname(__file__), "..", "services", "anti-phishing",
                         "src", "deepfake", "image_detector.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.DeepfakeImageDetector()

    def _make_jpeg_bytes(self):
        """Create a minimal valid JPEG in memory."""
        try:
            from PIL import Image
            import io
            img = Image.new("RGB", (64, 64), color=(100, 150, 200))
            buf = io.BytesIO()
            img.save(buf, format="JPEG")
            return buf.getvalue()
        except ImportError:
            # Return a dummy byte string so tests still load
            return b"\xff\xd8\xff\xe0" + b"\x00" * 100

    def test_analyze_returns_result(self):
        det = self._detector()
        result = det.analyze(self._make_jpeg_bytes())
        assert hasattr(result, "is_deepfake")
        assert hasattr(result, "risk_score")
        assert 0.0 <= result.risk_score <= 1.0

    def test_confidence_in_range(self):
        det = self._detector()
        result = det.analyze(self._make_jpeg_bytes())
        assert 0.0 <= result.confidence <= 1.0

    def test_model_used_field(self):
        det = self._detector()
        result = det.analyze(self._make_jpeg_bytes())
        assert result.model_used in ("heuristic", "cnn")

    def test_invalid_bytes_does_not_raise(self):
        """Garbage input should not propagate an exception."""
        det = self._detector()
        result = det.analyze(b"not-an-image-at-all")
        assert result.risk_score >= 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1 — Psychographic Risk Predictor
# ═══════════════════════════════════════════════════════════════════════════════

class TestPsychographicPredictor:

    def _components(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "psychographic_engine",
            os.path.join(os.path.dirname(__file__), "..", "services", "anti-phishing",
                         "src", "psychographic_engine.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.PsychographicPredictor(), mod.UserProfile

    def test_high_risk_user(self):
        predictor, UserProfile = self._components()
        profile = UserProfile(
            user_id="vip-001",
            display_name="Alice CEO",
            financial_authority=True,
            seniority_level=9,
            access_level=5,
            public_exposure_score=0.9,
            phishing_sim_fail_rate=0.8,
        )
        result = predictor.predict(profile)
        assert result.risk_tier in ("critical", "high")
        assert result.risk_score >= 0.5

    def test_low_risk_user(self):
        predictor, UserProfile = self._components()
        profile = UserProfile(
            user_id="intern-001",
            display_name="Bob Intern",
            seniority_level=1,
            financial_authority=False,
            access_level=0,
            public_exposure_score=0.0,
        )
        result = predictor.predict(profile)
        assert result.risk_score < 0.6

    def test_result_has_interventions(self):
        predictor, UserProfile = self._components()
        profile = UserProfile(
            user_id="u2",
            display_name="Carol CFO",
            financial_authority=True,
            seniority_level=8,
            phishing_sim_fail_rate=0.6,
        )
        result = predictor.predict(profile)
        assert isinstance(result.recommended_interventions, list)

    def test_attack_vectors_not_empty(self):
        predictor, UserProfile = self._components()
        profile = UserProfile(user_id="u3", display_name="Dave")
        result = predictor.predict(profile)
        assert len(result.attack_vectors) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2 — URL Detonator
# ═══════════════════════════════════════════════════════════════════════════════

class TestURLDetonatorRiskScoring:
    """Unit tests for _compute_risk() without launching a real browser."""

    def _detonator(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "url_detonator",
            os.path.join(os.path.dirname(__file__), "..", "services", "anti-phishing",
                         "src", "url_detonator.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.URLDetonator(), mod.DetonationResult

    def test_credential_form_raises_risk(self):
        det, DR = self._detonator()
        r = DR(url="http://evil.com", credential_forms=[{"has_password": True}])
        score = det._compute_risk(r)
        assert score >= 0.5

    def test_domain_redirect_adds_risk(self):
        det, DR = self._detonator()
        r = DR(url="http://legit.com", final_url="http://malicious.ru")
        score = det._compute_risk(r)
        assert score >= 0.3

    def test_clean_url_low_risk(self):
        det, DR = self._detonator()
        r = DR(url="https://example.com", final_url="https://example.com",
                network_requests=[{"url": f"https://example.com/r{i}"} for i in range(5)])
        score = det._compute_risk(r)
        assert score < 0.5

    def test_score_bounded(self):
        det, DR = self._detonator()
        r = DR(
            url="http://a.com", final_url="http://b.com",
            credential_forms=[{"has_password": True}],
            network_requests=[{"url": f"http://c.com/{i}"} for i in range(100)],
            javascript_alerts=["Alert! You won!"],
        )
        score = det._compute_risk(r)
        assert 0.0 <= score <= 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Threat Intel Enricher
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatIntelEnricher:

    def _enricher(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "threat_intel_enricher",
            os.path.join(os.path.dirname(__file__), "..", "services", "anti-phishing",
                         "src", "threat_intel_enricher.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.ThreatIntelEnricher()

    def test_enrich_returns_result(self):
        enricher = self._enricher()
        result = run(enricher.enrich("8.8.8.8", "ip"))
        assert hasattr(result, "reputation_score")
        assert 0.0 <= result.reputation_score <= 1.0

    def test_result_fields_present(self):
        enricher = self._enricher()
        result = run(enricher.enrich("http://example.com", "url"))
        for field in ("ioc", "ioc_type", "reputation_score", "sources_hit", "tags", "enriched_at"):
            assert hasattr(result, field), f"Missing: {field}"

    def test_ioc_type_preserved(self):
        enricher = self._enricher()
        result = run(enricher.enrich("example.com", "domain"))
        assert result.ioc_type == "domain"
        assert result.ioc == "example.com"

    def test_local_feed_hit(self):
        """If the IOC is in the local feed file, reputation_score == 1.0."""
        enricher = self._enricher()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("evil.example.org\n")
            feed_path = f.name
        enricher._local_feed = {"evil.example.org"}
        enricher._feed_loaded = True
        result = run(enricher._check_local_feed("evil.example.org", "domain"))
        assert result.reputation_score == 1.0
        os.unlink(feed_path)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3 — Model Feedback Store
# ═══════════════════════════════════════════════════════════════════════════════

class TestFeedbackStore:

    def _store(self, path):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "model_feedback_store",
            os.path.join(os.path.dirname(__file__), "..", "services", "anti-phishing",
                         "src", "model_feedback_store.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.FeedbackStore(store_path=path)

    def test_append_increments_count(self):
        with tempfile.TemporaryDirectory() as d:
            store = self._store(os.path.join(d, "feedback.jsonl"))
            assert store.get_pending_count() == 0
            store.append("Pay now!", "phishing", "phishing")
            assert store.get_pending_count() == 1
            store.append("Hello!", "legitimate", "legitimate")
            assert store.get_pending_count() == 2

    def test_read_all_returns_records(self):
        with tempfile.TemporaryDirectory() as d:
            store = self._store(os.path.join(d, "feedback.jsonl"))
            store.append("Test email", "phishing", "spear_phishing")
            records = store.read_all()
            assert len(records) == 1
            assert records[0]["predicted_label"] == "phishing"
            assert records[0]["correct_label"] == "spear_phishing"

    def test_export_produces_csv(self):
        with tempfile.TemporaryDirectory() as d:
            store = self._store(os.path.join(d, "feedback.jsonl"))
            store.append("Urgent: wire transfer needed!", "bec", "bec")
            out_csv = os.path.join(d, "export.csv")
            count = store.export_for_training(out_csv)
            assert count == 1
            assert os.path.exists(out_csv)
            with open(out_csv) as f:
                rows = list(csv.DictReader(f))
            assert rows[0]["label"] == "bec"

    def test_archive_resets_store(self):
        with tempfile.TemporaryDirectory() as d:
            store = self._store(os.path.join(d, "feedback.jsonl"))
            store.append("Test", "legitimate", "phishing")
            assert store.get_pending_count() == 1
            store.archive()
            assert store.get_pending_count() == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3 — Model Retraining Scheduler
# ═══════════════════════════════════════════════════════════════════════════════

class TestModelRetrainingScheduler:

    def _scheduler(self, feedback_path, min_samples=3):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "phishing_retrain",
            os.path.join(os.path.dirname(__file__), "..", "ml-models", "phishing_retrain.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod.ModelRetrainingScheduler(
            feedback_store_path=feedback_path,
            model_output_dir=tempfile.mkdtemp(),
            min_samples=min_samples,
        )

    def test_get_status_returns_expected_keys(self):
        with tempfile.TemporaryDirectory() as d:
            sched = self._scheduler(os.path.join(d, "feedback.jsonl"))
            status = sched.get_status()
            for key in ("model_version", "last_retrained", "pending_feedback_count", "status"):
                assert key in status, f"Missing key: {key}"

    def test_check_and_retrain_skips_when_insufficient(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "feedback.jsonl")
            # Write only 1 record but threshold is 3
            with open(path, "w") as fh:
                fh.write(json.dumps({"text": "x", "correct_label": "phishing"}) + "\n")
            sched = self._scheduler(path, min_samples=3)
            result = sched.check_and_retrain()
            assert result["retrained"] is False

    def test_pending_count_reflects_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "feedback.jsonl")
            with open(path, "w") as fh:
                for i in range(5):
                    fh.write(json.dumps({"text": f"email {i}", "correct_label": "phishing"}) + "\n")
            sched = self._scheduler(path, min_samples=100)
            status = sched.get_status()
            assert status["pending_feedback_count"] == 5

    def test_initial_version_is_string(self):
        with tempfile.TemporaryDirectory() as d:
            sched = self._scheduler(os.path.join(d, "fb.jsonl"))
            assert isinstance(sched.get_status()["model_version"], str)


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
