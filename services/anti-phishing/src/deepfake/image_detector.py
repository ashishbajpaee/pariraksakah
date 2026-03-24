"""
Deepfake Image Detector
Detects AI-generated / manipulated images using noise-pattern analysis,
EXIF inconsistency checks, and an optional CNN model path.
"""

import hashlib
import io
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("cybershield.antiphishing.deepfake_image")


@dataclass
class ImageAnalysisResult:
    is_deepfake: bool
    confidence: float
    risk_score: float
    signals: List[str] = field(default_factory=list)
    exif_anomalies: List[str] = field(default_factory=list)
    noise_variance: float = 0.0
    model_used: str = "heuristic"


class DeepfakeImageDetector:
    """
    Detects AI-generated or manipulated images.

    Heuristic checks (always available):
    - ELA (Error Level Analysis) — re-saves at lower JPEG quality, compares
      noise variance between original and re-saved.
    - EXIF consistency — checks for missing / contradictory metadata.
    - Colour-channel statistics — synthetic images often have different
      channel variance profiles.

    Optional CNN path: if a TorchScript `.pt` model is provided at
    `model_path`, it is used for binary classification (real / fake).
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = model_path
        self._loaded = False

    # ── Model loading ──────────────────────────────────────

    def load_model(self):
        """Try to load optional pre-trained TorchScript deepfake image model."""
        if not self.model_path:
            logger.info("No model_path provided — heuristic mode only")
            return
        try:
            import torch
            self.model = torch.jit.load(self.model_path, map_location="cpu")
            self.model.eval()
            self._loaded = True
            logger.info("Deepfake image model loaded from %s", self.model_path)
        except Exception as e:
            logger.warning("Deepfake image model load failed: %s — heuristic mode", e)

    # ── Public API ─────────────────────────────────────────

    def analyze(self, image_bytes: bytes) -> ImageAnalysisResult:
        """Analyse raw image bytes and return deepfake probability."""
        signals: List[str] = []
        exif_anomalies: List[str] = []
        score = 0.0

        # ── 1. EXIF analysis ──
        exif_score, exif_flags = self._check_exif(image_bytes)
        score += exif_score
        exif_anomalies.extend(exif_flags)
        if exif_flags:
            signals.append("exif_anomaly")

        # ── 2. ELA / noise variance ──
        noise_var, ela_score = self._error_level_analysis(image_bytes)
        score += ela_score
        if ela_score > 0.2:
            signals.append("ela_anomaly")

        # ── 3. Channel statistics ──
        chan_score = self._channel_stats(image_bytes)
        score += chan_score
        if chan_score > 0.15:
            signals.append("channel_uniformity")

        # ── 4. Optional CNN ──
        model_used = "heuristic"
        if self._loaded and self.model is not None:
            cnn_score = self._run_cnn(image_bytes)
            # Blend heuristic + CNN
            score = 0.4 * score + 0.6 * cnn_score
            model_used = "cnn"

        risk_score = float(np.clip(score, 0.0, 1.0))
        return ImageAnalysisResult(
            is_deepfake=risk_score >= 0.5,
            confidence=max(risk_score, 1 - risk_score),
            risk_score=round(risk_score, 4),
            signals=signals,
            exif_anomalies=exif_anomalies,
            noise_variance=round(noise_var, 6),
            model_used=model_used,
        )

    # ── Heuristic helpers ──────────────────────────────────

    def _check_exif(self, image_bytes: bytes):
        """Return (score_contribution, list_of_flags)."""
        flags = []
        score = 0.0
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(io.BytesIO(image_bytes))
            exif_data = img._getexif() or {}
            labeled = {TAGS.get(k, k): v for k, v in exif_data.items()}
            if not labeled:
                flags.append("no_exif")
                score += 0.15
            if "Make" not in labeled and "Software" not in labeled:
                flags.append("missing_camera_or_software")
                score += 0.10
            software = str(labeled.get("Software", "")).lower()
            ai_keywords = ["stable diffusion", "midjourney", "dall-e", "firefly", "gencraft"]
            for kw in ai_keywords:
                if kw in software:
                    flags.append(f"ai_software:{kw}")
                    score += 0.40
        except ImportError:
            flags.append("pillow_unavailable")
        except Exception as e:
            logger.debug("EXIF parse error: %s", e)
        return score, flags

    def _error_level_analysis(self, image_bytes: bytes):
        """Compute noise variance via ELA. Returns (noise_var, score)."""
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            # Save at lower quality to amplify compression artefacts
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=75)
            buf.seek(0)
            resaved = Image.open(buf).convert("RGB")
            diff = np.abs(np.array(img, dtype=np.float32) - np.array(resaved, dtype=np.float32))
            noise_var = float(np.var(diff))
            # Real photos have higher and more uniform ELA variance;
            # AI images often have unusually LOW or suspiciously HIGH variance.
            # We flag very low variance as suspicious.
            score = 0.25 if noise_var < 5.0 else 0.0
            return noise_var, score
        except Exception:
            return 0.0, 0.0

    def _channel_stats(self, image_bytes: bytes) -> float:
        """Detect unusual channel uniformity typical of GAN outputs."""
        try:
            from PIL import Image
            img = np.array(Image.open(io.BytesIO(image_bytes)).convert("RGB"), dtype=np.float32)
            r_var, g_var, b_var = np.var(img[:, :, 0]), np.var(img[:, :, 1]), np.var(img[:, :, 2])
            mean_var = (r_var + g_var + b_var) / 3.0
            max_dev = max(abs(r_var - mean_var), abs(g_var - mean_var), abs(b_var - mean_var))
            # Highly uniform channels → suspicious
            ratio = max_dev / (mean_var + 1e-6)
            return 0.20 if ratio < 0.05 else 0.0
        except Exception:
            return 0.0

    def _run_cnn(self, image_bytes: bytes) -> float:
        """Run TorchScript CNN model, return fake probability."""
        try:
            import torch
            from PIL import Image
            import torchvision.transforms as T
            transform = T.Compose([
                T.Resize((224, 224)),
                T.ToTensor(),
                T.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
            ])
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            tensor = transform(img).unsqueeze(0)
            with torch.no_grad():
                logits = self.model(tensor)
                prob = torch.softmax(logits, dim=-1).squeeze()
            return float(prob[1]) if prob.dim() > 0 else float(prob)
        except Exception as e:
            logger.warning("CNN inference failed: %s", e)
            return 0.0
