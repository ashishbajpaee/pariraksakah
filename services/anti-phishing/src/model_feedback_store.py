"""
Model Feedback Store
Collects analyst corrections on mis-classifications and persists them
to a JSONL file for periodic model retraining.
"""

import csv
import fcntl
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("cybershield.antiphishing.feedback_store")

DEFAULT_FEEDBACK_PATH = os.getenv(
    "FEEDBACK_STORE_PATH",
    os.path.join(os.path.dirname(__file__), "../../../datasets/feedback_store.jsonl"),
)


class FeedbackStore:
    """
    Thread-safe, file-backed store for analyst feedback on model predictions.

    Each record: {"text", "predicted_label", "correct_label", "ts"}
    Written as JSONL (one JSON object per line) for easy streaming reads.
    """

    def __init__(self, store_path: Optional[str] = None):
        self._path = store_path or DEFAULT_FEEDBACK_PATH
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._lock = threading.Lock()

    # ── Write ──────────────────────────────────────────────────────────────────

    def append(self, text: str, predicted_label: str, correct_label: str) -> int:
        """
        Persist one feedback record.
        Returns the updated pending-record count.
        """
        record = {
            "text": text,
            "predicted_label": predicted_label,
            "correct_label": correct_label,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.write(json.dumps(record) + "\n")
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        logger.debug("Feedback appended: predicted=%s correct=%s", predicted_label, correct_label)
        return self.get_pending_count()

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_pending_count(self) -> int:
        """Return number of feedback records not yet used for retraining."""
        if not os.path.exists(self._path):
            return 0
        try:
            with open(self._path, encoding="utf-8") as fh:
                return sum(1 for line in fh if line.strip())
        except Exception:
            return 0

    def read_all(self) -> List[Dict]:
        """Return all feedback records as a list of dicts."""
        if not os.path.exists(self._path):
            return []
        records = []
        try:
            with open(self._path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.warning("Failed to read feedback store: %s", e)
        return records

    # ── Export for retraining ──────────────────────────────────────────────────

    def export_for_training(self, out_csv: str) -> int:
        """
        Export feedback records to a CSV with columns: text, label
        (using `correct_label` as ground truth).
        Returns number of records exported.
        """
        records = self.read_all()
        if not records:
            logger.info("No feedback records to export")
            return 0
        os.makedirs(os.path.dirname(out_csv), exist_ok=True)
        with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["text", "label"])
            writer.writeheader()
            for r in records:
                writer.writerow({"text": r["text"], "label": r["correct_label"]})
        logger.info("Exported %d feedback records to %s", len(records), out_csv)
        return len(records)

    # ── Archival ───────────────────────────────────────────────────────────────

    def archive(self, archive_path: Optional[str] = None) -> str:
        """Move current feedback file to an archive and reset for fresh collection."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive = archive_path or f"{self._path}.{ts}.archive"
        with self._lock:
            if os.path.exists(self._path):
                os.rename(self._path, archive)
                logger.info("Archived feedback to %s", archive)
        return archive
