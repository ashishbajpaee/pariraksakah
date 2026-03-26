"""
Deliverable 2: Cryptographic Asset Scanner — CBOM Generator
Scans the entire codebase, infrastructure configs, TLS certs, and
data pipelines to discover all cryptographic usage. Generates a
Cryptographic Bill of Materials (CBOM) with quantum vulnerability scores.
"""
import asyncio
import json
import os
import re
import ssl
import hashlib
import logging
import socket
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from contextlib import asynccontextmanager

import asyncpg
import redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cbom_scanner")

# ═══ Configuration ═══
PG_DSN = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "changeme_redis")
SCAN_ROOT = os.getenv("SCAN_ROOT", "/app/codebase")
PQC_DATASET = os.getenv("PQC_DATASET", "/datasets/PQC-APIdocs-UpdatedCopyright")

# ═══ Quantum Vulnerability Classification ═══
QUANTUM_CLASSIFICATION = {
    # 🔴 Quantum-Vulnerable — can be broken by Shor's / Grover's
    "RSA": {"status": "vulnerable", "color": "red", "score": 95, "replacement": "ML-KEM (CRYSTALS-Kyber)"},
    "RSA-1024": {"status": "vulnerable", "color": "red", "score": 100, "replacement": "ML-KEM-768"},
    "RSA-2048": {"status": "vulnerable", "color": "red", "score": 95, "replacement": "ML-KEM-1024"},
    "RSA-4096": {"status": "vulnerable", "color": "red", "score": 90, "replacement": "ML-KEM-1024"},
    "ECDSA": {"status": "vulnerable", "color": "red", "score": 95, "replacement": "ML-DSA (CRYSTALS-Dilithium)"},
    "ECDH": {"status": "vulnerable", "color": "red", "score": 95, "replacement": "ML-KEM (CRYSTALS-Kyber)"},
    "ECC": {"status": "vulnerable", "color": "red", "score": 95, "replacement": "ML-DSA-65"},
    "DSA": {"status": "vulnerable", "color": "red", "score": 95, "replacement": "FALCON / SPHINCS+"},
    "DH": {"status": "vulnerable", "color": "red", "score": 90, "replacement": "ML-KEM"},
    "Diffie-Hellman": {"status": "vulnerable", "color": "red", "score": 90, "replacement": "ML-KEM"},
    "Ed25519": {"status": "vulnerable", "color": "red", "score": 85, "replacement": "ML-DSA-44"},
    "X25519": {"status": "vulnerable", "color": "red", "score": 85, "replacement": "ML-KEM-512"},

    # 🟡 Partially Safe — needs upgrade
    "AES-128": {"status": "partial", "color": "yellow", "score": 40, "replacement": "AES-256"},
    "3DES": {"status": "partial", "color": "yellow", "score": 65, "replacement": "AES-256"},
    "DES": {"status": "vulnerable", "color": "red", "score": 100, "replacement": "AES-256"},
    "SHA-1": {"status": "partial", "color": "yellow", "score": 50, "replacement": "SHA-3 / SHAKE-256"},
    "MD5": {"status": "vulnerable", "color": "red", "score": 80, "replacement": "SHA-3-256"},
    "SHA-256": {"status": "partial", "color": "yellow", "score": 25, "replacement": "SHA-3-256 (Grover halves effective bits)"},
    "HMAC-SHA256": {"status": "partial", "color": "yellow", "score": 20, "replacement": "HMAC-SHA3-256"},

    # 🟢 Quantum-Safe
    "AES-256": {"status": "safe", "color": "green", "score": 5, "replacement": "N/A (quantum-safe)"},
    "SHA-3": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "SHA-3-256": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "SHA-3-512": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "SHAKE-128": {"status": "safe", "color": "green", "score": 5, "replacement": "SHAKE-256"},
    "SHAKE-256": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "ML-KEM": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A (PQC-native)"},
    "ML-DSA": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A (PQC-native)"},
    "CRYSTALS-Kyber": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "CRYSTALS-Dilithium": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "FALCON": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "SPHINCS+": {"status": "safe", "color": "green", "score": 0, "replacement": "N/A"},
    "ChaCha20-Poly1305": {"status": "safe", "color": "green", "score": 5, "replacement": "N/A"},
}

# ═══ Regex Patterns for Crypto Discovery ═══
CRYPTO_PATTERNS = {
    "RSA": [
        r"RSA[_\-\s]?(1024|2048|3072|4096)",
        r"crypto[/.]rsa", r"RSAPublicKey", r"RSAPrivateKey",
        r"rsa\.GenerateKey", r"NewRSAKey", r"RSA_generate_key",
        r"PKCS1v15", r"PKCS8", r"BEGIN RSA",
    ],
    "ECDSA": [
        r"ECDSA", r"ecdsa\.", r"crypto[/.]ecdsa",
        r"SigningMethodES\d+", r"EC_KEY", r"elliptic\.P\d+",
        r"secp\d+[rk]\d", r"prime256v1",
    ],
    "ECDH": [r"ECDH", r"ecdh\.", r"X25519", r"x25519"],
    "Ed25519": [r"Ed25519", r"ed25519", r"crypto[/.]ed25519"],
    "DH": [r"Diffie.?Hellman", r"DH_generate", r"diffie_hellman"],
    "DSA": [r"(?<![A-Za-z])DSA(?![A-Za-z])", r"crypto[/.]dsa"],
    "AES-128": [r"AES[_\-]?128", r"aes128", r"AES\.block_size.*16"],
    "AES-256": [r"AES[_\-]?256", r"aes256"],
    "3DES": [r"3DES", r"Triple.?DES", r"DESede", r"des3"],
    "DES": [r"(?<![3A-Za-z])DES(?![A-Za-z3])", r"des_cbc"],
    "SHA-1": [r"SHA[_\-]?1(?!\d)", r"sha1", r"SHA1"],
    "MD5": [r"(?<![A-Za-z])MD5(?![A-Za-z])", r"md5\(", r"hashlib\.md5"],
    "SHA-256": [r"SHA[_\-]?256", r"sha256", r"SHA256"],
    "SHA-3": [r"SHA[_\-]?3", r"sha3", r"SHAKE"],
    "HMAC-SHA256": [r"HMAC[_\-]?SHA[_\-]?256", r"hmac\.new.*sha256"],
    "ChaCha20-Poly1305": [r"ChaCha20", r"chacha20", r"Poly1305"],
    "JWT": [r"jwt[\.\-_]", r"JSON.?Web.?Token", r"SigningMethodHS\d+", r"HS256", r"RS256", r"ES256"],
    "TLS": [r"TLS[_\- ]?1\.[0-3]", r"SSLv[23]", r"tls\.Config", r"ssl\.create_default"],
    "PKCS": [r"PKCS#?\d+", r"pkcs\d+"],
}

# File extensions to scan
SCAN_EXTENSIONS = {".go", ".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".toml", ".yaml", ".yml",
                   ".json", ".env", ".cfg", ".conf", ".pem", ".crt", ".key", ".sh", ".sql"}

# ═══ CBOM Asset ═══
class CryptoAsset(BaseModel):
    id: str
    algorithm: str
    category: str  # asymmetric, symmetric, hash, signature, protocol, token
    location: str
    file_path: str
    line_number: int
    context: str
    key_size: Optional[int] = None
    quantum_status: str  # vulnerable, partial, safe
    vulnerability_score: int  # 0-100
    replacement: str
    risk_level: str  # critical, high, medium, low
    discovered_at: str


# ═══ Source Code Scanner ═══
def scan_source_code(root_dir: str) -> List[CryptoAsset]:
    """Recursively scan source code for cryptographic usage."""
    assets: List[CryptoAsset] = []
    root = Path(root_dir)

    if not root.exists():
        logger.warning(f"Scan root {root_dir} does not exist, scanning /app instead")
        root = Path("/app")

    for fpath in root.rglob("*"):
        if fpath.is_file() and fpath.suffix in SCAN_EXTENSIONS:
            try:
                content = fpath.read_text(errors="ignore")
                lines = content.split("\n")

                for algo, patterns in CRYPTO_PATTERNS.items():
                    for pattern in patterns:
                        for i, line in enumerate(lines, 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                classification = QUANTUM_CLASSIFICATION.get(algo, {})
                                q_status = classification.get("status", "unknown")
                                vuln_score = classification.get("score", 50)
                                replacement = classification.get("replacement", "Review needed")

                                # Determine category
                                category = "unknown"
                                if algo in ("RSA", "ECDSA", "ECDH", "DH", "DSA", "Ed25519", "ECC"):
                                    category = "asymmetric"
                                elif algo in ("AES-128", "AES-256", "3DES", "DES", "ChaCha20-Poly1305"):
                                    category = "symmetric"
                                elif algo in ("SHA-1", "MD5", "SHA-256", "SHA-3", "HMAC-SHA256"):
                                    category = "hash"
                                elif algo in ("JWT",):
                                    category = "token"
                                elif algo in ("TLS",):
                                    category = "protocol"
                                elif algo in ("PKCS",):
                                    category = "standard"

                                # Risk level from vuln score
                                risk = "critical" if vuln_score >= 80 else "high" if vuln_score >= 50 else "medium" if vuln_score >= 20 else "low"

                                # Extract key size from context
                                key_size = None
                                size_match = re.search(r"(\d{3,4})", line)
                                if size_match and int(size_match.group(1)) in (128, 256, 512, 1024, 2048, 3072, 4096):
                                    key_size = int(size_match.group(1))

                                asset = CryptoAsset(
                                    id=str(uuid4()),
                                    algorithm=algo,
                                    category=category,
                                    location=f"{fpath.relative_to(root)}",
                                    file_path=str(fpath),
                                    line_number=i,
                                    context=line.strip()[:200],
                                    key_size=key_size,
                                    quantum_status=q_status,
                                    vulnerability_score=vuln_score,
                                    replacement=replacement,
                                    risk_level=risk,
                                    discovered_at=datetime.utcnow().isoformat(),
                                )
                                assets.append(asset)
                                break  # one match per pattern per file
            except Exception as e:
                logger.debug(f"Error scanning {fpath}: {e}")
    return assets


# ═══ TLS/SSL Scanner ═══
def scan_tls_endpoints(hosts: List[Tuple[str, int]]) -> List[CryptoAsset]:
    """Scan TLS endpoints for cipher suites and certificate algorithms."""
    assets = []
    for host, port in hosts:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Analyze cipher suite
                    cipher_name = cipher[0] if cipher else "UNKNOWN"
                    algo = "UNKNOWN"
                    if "RSA" in cipher_name:
                        algo = "RSA"
                    elif "ECDHE" in cipher_name or "ECDH" in cipher_name:
                        algo = "ECDH"
                    elif "DHE" in cipher_name:
                        algo = "DH"

                    classification = QUANTUM_CLASSIFICATION.get(algo, {})
                    assets.append(CryptoAsset(
                        id=str(uuid4()), algorithm=algo, category="protocol",
                        location=f"TLS:{host}:{port}", file_path=f"tls://{host}:{port}",
                        line_number=0, context=f"Cipher={cipher_name} Version={version}",
                        quantum_status=classification.get("status", "unknown"),
                        vulnerability_score=classification.get("score", 50),
                        replacement=classification.get("replacement", "TLS 1.3 + ML-KEM"),
                        risk_level="high" if algo in ("RSA", "DH") else "medium",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))
        except Exception as e:
            logger.warning(f"TLS scan failed for {host}:{port}: {e}")
    return assets


# ═══ Infrastructure Scanner ═══
def scan_infrastructure_configs() -> List[CryptoAsset]:
    """Scan Docker, Kubernetes, and infrastructure files for crypto configs."""
    assets = []
    config_patterns = {
        "docker-compose": ["--requirepass", "POSTGRES_PASSWORD", "JWT_SECRET", "NEO4J_PASSWORD"],
        "env_file": ["SECRET_KEY", "API_KEY", "PRIVATE_KEY", "ENCRYPTION_KEY"],
    }

    # Scan for .pem, .crt, .key files
    for ext in (".pem", ".crt", ".key", ".p12", ".pfx"):
        for fpath in Path("/app").rglob(f"*{ext}"):
            assets.append(CryptoAsset(
                id=str(uuid4()), algorithm="RSA/ECC (cert)", category="certificate",
                location=str(fpath), file_path=str(fpath), line_number=0,
                context=f"Certificate/key file: {fpath.name}",
                quantum_status="vulnerable", vulnerability_score=85,
                replacement="ML-DSA hybrid certificate",
                risk_level="critical",
                discovered_at=datetime.utcnow().isoformat(),
            ))
    return assets


# ═══ CBOM Generator ═══
def generate_cbom(assets: List[CryptoAsset]) -> dict:
    """Generate the Cryptographic Bill of Materials."""
    vulnerable = [a for a in assets if a.quantum_status == "vulnerable"]
    partial = [a for a in assets if a.quantum_status == "partial"]
    safe = [a for a in assets if a.quantum_status == "safe"]

    total_risk = sum(a.vulnerability_score for a in assets)
    max_risk = len(assets) * 100 if assets else 1
    quantum_readiness = max(0, 100 - int(total_risk / max_risk * 100))

    cbom = {
        "cbom_version": "1.0",
        "generated_at": datetime.utcnow().isoformat(),
        "scan_root": SCAN_ROOT,
        "summary": {
            "total_assets": len(assets),
            "vulnerable_red": len(vulnerable),
            "partial_yellow": len(partial),
            "safe_green": len(safe),
            "quantum_readiness_score": quantum_readiness,
        },
        "risk_breakdown": {
            "critical": len([a for a in assets if a.risk_level == "critical"]),
            "high": len([a for a in assets if a.risk_level == "high"]),
            "medium": len([a for a in assets if a.risk_level == "medium"]),
            "low": len([a for a in assets if a.risk_level == "low"]),
        },
        "algorithm_inventory": {},
        "assets": [a.model_dump() for a in assets],
    }

    # Group by algorithm
    algo_groups: Dict[str, list] = {}
    for a in assets:
        algo_groups.setdefault(a.algorithm, []).append(a)
    for algo, group in algo_groups.items():
        classification = QUANTUM_CLASSIFICATION.get(algo, {})
        cbom["algorithm_inventory"][algo] = {
            "count": len(group),
            "status": classification.get("status", "unknown"),
            "color": classification.get("color", "grey"),
            "vulnerability_score": classification.get("score", 50),
            "replacement": classification.get("replacement", "Review needed"),
            "locations": list(set(a.location for a in group)),
        }

    return cbom


# ═══ FastAPI App ═══
pg_pool: Optional[asyncpg.Pool] = None
rds: Optional[redis.Redis] = None
cached_cbom: Optional[dict] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pg_pool, rds
    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=1, max_size=3)
    except Exception as e:
        logger.error(f"DB connection failed: {e}")
    rds = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
    logger.info("CBOM Scanner service started")
    yield
    if pg_pool:
        await pg_pool.close()

app = FastAPI(title="Quantum Crypto — CBOM Scanner", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "quantum-cbom-scanner"}


@app.post("/scan")
async def run_scan(scan_path: str = SCAN_ROOT):
    """Run a full cryptographic asset scan and generate CBOM."""
    global cached_cbom
    logger.info(f"Starting CBOM scan at {scan_path}...")

    # Scan source code
    code_assets = scan_source_code(scan_path)

    # Scan TLS endpoints
    tls_hosts = [
        ("api-gateway", 8000), ("kafka", 9092), ("timescaledb", 5432),
        ("neo4j", 7687), ("redis", 6379), ("mlflow", 5000),
    ]
    tls_assets = scan_tls_endpoints(tls_hosts)

    # Scan infrastructure
    infra_assets = scan_infrastructure_configs()

    all_assets = code_assets + tls_assets + infra_assets
    cbom = generate_cbom(all_assets)
    cached_cbom = cbom

    # Cache in Redis
    if rds:
        rds.set("quantum:cbom:latest", json.dumps(cbom, default=str), ex=86400)
        rds.set("quantum:readiness_score", cbom["summary"]["quantum_readiness_score"], ex=86400)

    logger.info(f"Scan complete: {len(all_assets)} assets found, readiness={cbom['summary']['quantum_readiness_score']}%")
    return cbom


@app.get("/cbom")
async def get_cbom():
    """Return the latest CBOM."""
    if cached_cbom:
        return cached_cbom
    if rds:
        cached = rds.get("quantum:cbom:latest")
        if cached:
            return json.loads(cached)
    raise HTTPException(404, "No CBOM available. Run POST /scan first.")


@app.get("/readiness")
async def readiness_score():
    """Get the current quantum readiness score."""
    score = 0
    if rds:
        score = int(rds.get("quantum:readiness_score") or 0)
    elif cached_cbom:
        score = cached_cbom["summary"]["quantum_readiness_score"]
    return {"quantum_readiness_score": score, "target": 100}


@app.get("/algorithms")
async def list_algorithms():
    """List all known algorithms and their quantum classification."""
    return {"algorithms": QUANTUM_CLASSIFICATION}


@app.get("/metrics")
async def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    score = 0
    total = 0
    vulnerable = 0
    if cached_cbom:
        score = cached_cbom["summary"]["quantum_readiness_score"]
        total = cached_cbom["summary"]["total_assets"]
        vulnerable = cached_cbom["summary"]["vulnerable_red"]
    return PlainTextResponse(
        f'quantum_readiness_score {score}\n'
        f'quantum_total_crypto_assets {total}\n'
        f'quantum_vulnerable_assets {vulnerable}\n',
        media_type="text/plain",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("QUANTUM_SCANNER_PORT", "8030")))
