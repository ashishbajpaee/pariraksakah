"""
Model Retraining Scheduler
Wraps the existing finetune_classifier() function and manages the model
lifecycle: checks pending feedback, triggers retraining when threshold
is met, and tracks model version metadata.
"""

import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("cybershield.mlmodels.phishing_retrain")

# ── Configurable thresholds ────────────────────────────────────────────────────

MIN_RETRAIN_SAMPLES = int(os.getenv("MIN_RETRAIN_SAMPLES", "200"))
MODEL_OUTPUT_DIR    = os.getenv("MODEL_OUTPUT_DIR", "ml-models/saved/phishing_classifier")
FEEDBACK_STORE_PATH = os.getenv(
    "FEEDBACK_STORE_PATH",
    "datasets/feedback_store.jsonl",
)


class ModelRetrainingScheduler:
    """
    Manages phishing classifier retraining lifecycle.

    Typical usage (run periodically or triggered by the feedback endpoint):

        scheduler = ModelRetrainingScheduler()
        result = scheduler.check_and_retrain()
        print(result)          # {"retrained": True, "samples_used": 312, ...}
    """

    def __init__(
        self,
        feedback_store_path: Optional[str] = None,
        model_output_dir: Optional[str] = None,
        min_samples: int = MIN_RETRAIN_SAMPLES,
    ):
        self._feedback_path = feedback_store_path or FEEDBACK_STORE_PATH
        self._output_dir    = model_output_dir or MODEL_OUTPUT_DIR
        self._min_samples   = min_samples
        self._status: Dict[str, Any] = {
            "model_version": "1.0.0",
            "last_retrained": None,
            "pending_feedback_count": 0,
            "status": "idle",
            "last_error": None,
        }

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Return current model lifecycle state."""
        self._status["pending_feedback_count"] = self._count_pending()
        return dict(self._status)

    def check_and_retrain(self) -> Dict[str, Any]:
        """
        Check if enough feedback has accumulated; if so, trigger retraining.
        Returns a status dict with `retrained: bool` and diagnostics.
        """
        pending = self._count_pending()
        self._status["pending_feedback_count"] = pending

        if pending < self._min_samples:
            logger.info(
                "Skipping retrain: %d/%d feedback samples available",
                pending, self._min_samples,
            )
            return {
                "retrained": False,
                "reason": f"Insufficient samples: {pending} < {self._min_samples}",
                **self.get_status(),
            }

        return self._run_retrain(pending)

    def force_retrain(self) -> Dict[str, Any]:
        """Trigger retraining unconditionally (admin/debug use)."""
        pending = self._count_pending()
        if pending == 0:
            return {"retrained": False, "reason": "No feedback records at all", **self.get_status()}
        return self._run_retrain(pending)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _count_pending(self) -> int:
        """Count JSONL lines in the feedback store file."""
        if not os.path.exists(self._feedback_path):
            return 0
        try:
            with open(self._feedback_path, encoding="utf-8") as fh:
                return sum(1 for line in fh if line.strip())
        except Exception:
            return 0

    def _run_retrain(self, sample_count: int) -> Dict[str, Any]:
        """Export feedback to CSV and call finetune_classifier."""
        self._status["status"] = "retraining"
        logger.info("Starting retraining with %d feedback samples", sample_count)

        try:
            # Export feedback to a temp CSV
            export_csv = tempfile.NamedTemporaryFile(
                suffix=".csv", delete=False, prefix="phishing_feedback_"
            ).name
            exported = self._export_feedback(export_csv)

            if exported == 0:
                self._status["status"] = "idle"
                return {"retrained": False, "reason": "Export produced 0 records", **self.get_status()}

            # Import and call the existing fine-tuner
            # We add the services/anti-phishing/src path to allow relative import
            import importlib.util, sys

            _src_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "services",
                "anti-phishing",
                "src",
            )
            spec = importlib.util.spec_from_file_location(
                "phishing_classifier",
                os.path.join(_src_path, "phishing_classifier.py"),
            )
            pc_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(pc_module)  # type: ignore[union-attr]

            pc_module.finetune_classifier(
                train_csv=export_csv,
                output_dir=self._output_dir,
            )

            # Archive used feedback
            archive_path = self._feedback_path + f".{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.archive"
            os.rename(self._feedback_path, archive_path)

            # Bump version
            major, minor, patch = self._status["model_version"].split(".")
            self._status["model_version"] = f"{major}.{minor}.{int(patch) + 1}"
            self._status["last_retrained"] = datetime.now(timezone.utc).isoformat()
            self._status["pending_feedback_count"] = 0
            self._status["status"] = "active"
            self._status["last_error"] = None

            logger.info("Retraining complete. New version: %s", self._status["model_version"])
            return {
                "retrained": True,
                "samples_used": exported,
                "new_model_version": self._status["model_version"],
                **self.get_status(),
            }

        except Exception as e:
            logger.error("Retraining failed: %s", e, exc_info=True)
            self._status["status"] = "error"
            self._status["last_error"] = str(e)
            return {"retrained": False, "error": str(e), **self.get_status()}
        finally:
            # Best-effort cleanup
            try:
                os.unlink(export_csv)
            except Exception:
                pass

    def _export_feedback(self, out_csv: str) -> int:
        """Export JSONL feedback to CSV. Returns count of exported records."""
        import csv, json

        records = []
        try:
            with open(self._feedback_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            return 0

        if not records:
            return 0

        with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["text", "label"])
            writer.writeheader()
            for r in records:
                writer.writerow({"text": r.get("text", ""), "label": r.get("correct_label", "legitimate")})

        return len(records)
