"""
Threat Intelligence Enricher
Aggregates IOC reputation data from mocked VirusTotal, AbuseIPDB,
and a local threat feed. Designed to be swapped for real API keys
via environment variables.
"""

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("cybershield.antiphishing.threat_intel")

# ── Configuration (set real keys via env to enable live lookups) ──────────────

VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Local threat feed — a newline-delimited list of known-bad IOCs bundled in
# datasets/ and mounted into the container.
LOCAL_FEED_PATH = os.getenv(
    "LOCAL_THREAT_FEED",
    os.path.join(os.path.dirname(__file__), "../../../../datasets/threat_feed.txt"),
)

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str                        # url | ip | domain | hash
    reputation_score: float              # 0.0 (clean) → 1.0 (malicious)
    sources_hit: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    last_seen: Optional[str] = None
    raw: Dict = field(default_factory=dict)
    enriched_at: str = ""

    def __post_init__(self):
        if not self.enriched_at:
            self.enriched_at = datetime.now(timezone.utc).isoformat()


# ── Enricher ──────────────────────────────────────────────────────────────────

class ThreatIntelEnricher:
    """
    Multi-source IOC enrichment aggregator.

    Source priority:
    1. Local threat feed (fastest, always available)
    2. VirusTotal (requires VT_API_KEY env var)
    3. AbuseIPDB (requires ABUSEIPDB_API_KEY env var, IP-only)
    """

    def __init__(self):
        self._local_feed: set = set()
        self._feed_loaded = False

    # ── Public interface ──────────────────────────────────────────────────────

    async def enrich(self, ioc: str, ioc_type: str = "url") -> EnrichmentResult:
        """Enrich a single IOC and return aggregated reputation."""
        self._ensure_local_feed()
        results: List[EnrichmentResult] = []

        # Run lookups concurrently
        tasks = [self._check_local_feed(ioc, ioc_type)]
        if VT_API_KEY:
            tasks.append(self._virustotal_lookup(ioc, ioc_type))
        if ABUSEIPDB_API_KEY and ioc_type == "ip":
            tasks.append(self._abuseipdb_lookup(ioc))
        if not VT_API_KEY:
            tasks.append(self._virustotal_mock(ioc, ioc_type))

        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for r in gathered:
            if isinstance(r, EnrichmentResult):
                results.append(r)

        return self._merge(ioc, ioc_type, results)

    # ── Local feed ────────────────────────────────────────────────────────────

    def _ensure_local_feed(self):
        if self._feed_loaded:
            return
        try:
            with open(LOCAL_FEED_PATH) as fh:
                self._local_feed = {line.strip().lower() for line in fh if line.strip()}
            logger.info("Local threat feed loaded: %d IOCs", len(self._local_feed))
        except FileNotFoundError:
            logger.info("No local threat feed found at %s — skipping", LOCAL_FEED_PATH)
        finally:
            self._feed_loaded = True

    async def _check_local_feed(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        hit = ioc.lower() in self._local_feed
        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            reputation_score=1.0 if hit else 0.0,
            sources_hit=["local_feed"] if hit else [],
            tags=["threat_feed_match"] if hit else [],
        )

    # ── VirusTotal (live) ─────────────────────────────────────────────────────

    async def _virustotal_lookup(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """Query VirusTotal v3 API — requires VT_API_KEY."""
        try:
            import httpx
            # Encode the IOC as VirusTotal expects
            if ioc_type in ("url", "domain"):
                import base64
                resource_id = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
                resource_type = "urls" if ioc_type == "url" else "domains"
            elif ioc_type == "ip":
                resource_id = ioc
                resource_type = "ip_addresses"
            else:
                resource_id = ioc
                resource_type = "files"

            url = f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers={"x-apikey": VT_API_KEY})
                if resp.status_code != 200:
                    raise ValueError(f"VT status {resp.status_code}")
                data = resp.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = malicious / total
            tags = data.get("data", {}).get("attributes", {}).get("tags", [])

            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                reputation_score=round(score, 4),
                sources_hit=["virustotal"],
                tags=tags,
                last_seen=data.get("data", {}).get("attributes", {}).get("last_modification_date"),
                raw={"vt_stats": stats},
            )
        except Exception as e:
            logger.warning("VirusTotal lookup failed for %s: %s", ioc, e)
            return EnrichmentResult(ioc=ioc, ioc_type=ioc_type, reputation_score=0.0)

    # ── VirusTotal mock (when no key) ─────────────────────────────────────────

    async def _virustotal_mock(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """Deterministic mock that returns a stable score based on IOC hash."""
        digest = hashlib.sha256(ioc.encode()).hexdigest()
        score = int(digest[:2], 16) / 255.0   # 0-1 from first 2 hex chars
        is_flagged = score > 0.7
        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            reputation_score=round(score, 4),
            sources_hit=["virustotal_mock"],
            tags=["mock_high_risk"] if is_flagged else [],
            last_seen=datetime.now(timezone.utc).isoformat(),
            raw={"note": "VT mock — set VIRUSTOTAL_API_KEY for live data"},
        )

    # ── AbuseIPDB (live) ──────────────────────────────────────────────────────

    async def _abuseipdb_lookup(self, ip: str) -> EnrichmentResult:
        """Query AbuseIPDB v2 API — requires ABUSEIPDB_API_KEY."""
        try:
            import httpx
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, params=params, headers=headers)
                data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0) / 100.0
            return EnrichmentResult(
                ioc=ip,
                ioc_type="ip",
                reputation_score=round(score, 4),
                sources_hit=["abuseipdb"],
                tags=data.get("usageType", "").split(",") if data.get("usageType") else [],
                last_seen=data.get("lastReportedAt"),
                raw={"total_reports": data.get("totalReports", 0)},
            )
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return EnrichmentResult(ioc=ip, ioc_type="ip", reputation_score=0.0)

    # ── Aggregation ───────────────────────────────────────────────────────────

    def _merge(self, ioc: str, ioc_type: str, results: List[EnrichmentResult]) -> EnrichmentResult:
        """Merge multiple source results into a single verdict."""
        if not results:
            return EnrichmentResult(ioc=ioc, ioc_type=ioc_type, reputation_score=0.0)

        # Source weights
        weights = {"local_feed": 1.0, "virustotal": 0.8, "virustotal_mock": 0.5, "abuseipdb": 0.7}
        total_weight = 0.0
        weighted_score = 0.0
        all_sources: List[str] = []
        all_tags: List[str] = []
        last_seen = None

        for r in results:
            for s in r.sources_hit:
                w = weights.get(s, 0.5)
                weighted_score += r.reputation_score * w
                total_weight += w
                all_sources.append(s)
            all_tags.extend(r.tags)
            if r.last_seen:
                last_seen = r.last_seen

        final_score = weighted_score / total_weight if total_weight else 0.0
        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            reputation_score=round(float(final_score), 4),
            sources_hit=list(set(all_sources)),
            tags=list(set(all_tags)),
            last_seen=last_seen,
        )
