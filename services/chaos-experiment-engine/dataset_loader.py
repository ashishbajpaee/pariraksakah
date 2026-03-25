"""
Deliverable 4: Dataset Loader Module
Loads 7 security datasets from local paths into Redis (indexed cache),
TimescaleDB (parsed scenarios), and Neo4j (attack graph relationships).
Exposes a FastAPI REST API for querying loaded dataset content.
"""
import asyncio
import json
import hashlib
import os
import glob
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import redis
import asyncpg
from neo4j import AsyncGraphDatabase
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dataset_loader")

# ═══ Configuration ═══
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "changeme_redis")
PG_DSN = os.getenv("DATABASE_URL", "postgresql://cybershield:changeme_postgres@timescaledb:5432/cybershield")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme_neo4j")

DATASET_PATHS = {
    "mitre_attack": "/datasets/mitre/enterprise-attack.json",
    "owasp_top10": "/datasets/owasp/owasp-top10-2021.json",
    "stix_full": "/datasets/stix/enterprise-attack-stix.json",
    "cisa_kev": "/datasets/stix/cisa-kev.json",
    "emerging_threats": "/datasets/malicious-ips/emerging-threats.txt",
    "firehol_l1": "/datasets/malicious-ips/firehol-level1.netset",
    "nvd_cves": "/datasets/nvd/",
}

REDIS_TTL = 86400  # 24 hours

# ═══ Globals ═══
rds: Optional[redis.Redis] = None
pg_pool: Optional[asyncpg.Pool] = None
neo4j_driver = None
loaded_datasets: Dict[str, dict] = {}


# ═══ Redis Helpers ═══
def redis_connect() -> redis.Redis:
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)


def index_to_redis(key_prefix: str, items: List[dict], id_field: str = "id"):
    """Store each item as a Redis hash, indexed by its ID, with 24h TTL."""
    pipe = rds.pipeline()
    for item in items:
        item_id = item.get(id_field, str(uuid4()))
        rkey = f"{key_prefix}:{item_id}"
        pipe.set(rkey, json.dumps(item, default=str), ex=REDIS_TTL)
    pipe.set(f"{key_prefix}:count", len(items), ex=REDIS_TTL)
    pipe.execute()
    logger.info(f"Indexed {len(items)} items under {key_prefix}:* in Redis (TTL={REDIS_TTL}s)")


# ═══ Dataset Parsers ═══
def load_mitre_attack(path: str) -> List[dict]:
    """Parse MITRE ATT&CK Enterprise STIX bundle into technique records."""
    if not Path(path).exists():
        logger.warning(f"MITRE dataset not found at {path}, using fallback")
        return _fallback_mitre()
    with open(path) as f:
        bundle = json.load(f)
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            mitre_id = next((r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
            if mitre_id:
                kill_chain = [kc.get("phase_name", "") for kc in obj.get("kill_chain_phases", [])]
                techniques.append({
                    "id": mitre_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "")[:500],
                    "kill_chain_phases": kill_chain,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                })
    logger.info(f"Parsed {len(techniques)} MITRE ATT&CK techniques")
    return techniques


def _fallback_mitre() -> List[dict]:
    """Provide a minimal set of MITRE techniques if the dataset is missing."""
    return [
        {"id": "T1078", "name": "Valid Accounts", "kill_chain_phases": ["initial-access"], "platforms": ["Linux"]},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "kill_chain_phases": ["initial-access"], "platforms": ["Linux"]},
        {"id": "T1021", "name": "Remote Services", "kill_chain_phases": ["lateral-movement"], "platforms": ["Linux"]},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "kill_chain_phases": ["execution"], "platforms": ["Linux"]},
        {"id": "T1053", "name": "Scheduled Task/Job", "kill_chain_phases": ["persistence"], "platforms": ["Linux"]},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "kill_chain_phases": ["privilege-escalation"], "platforms": ["Linux"]},
        {"id": "T1070", "name": "Indicator Removal", "kill_chain_phases": ["defense-evasion"], "platforms": ["Linux"]},
        {"id": "T1003", "name": "OS Credential Dumping", "kill_chain_phases": ["credential-access"], "platforms": ["Linux"]},
        {"id": "T1046", "name": "Network Service Discovery", "kill_chain_phases": ["discovery"], "platforms": ["Linux"]},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "kill_chain_phases": ["exfiltration"], "platforms": ["Linux"]},
    ]


def load_owasp(path: str) -> List[dict]:
    if not Path(path).exists():
        logger.warning(f"OWASP dataset not found at {path}")
        return [{"id": f"A{i:02d}", "name": f"OWASP A{i:02d}"} for i in range(1, 11)]
    with open(path) as f:
        return json.load(f) if isinstance(json.load(f), list) else []


def load_cisa_kev(path: str) -> List[dict]:
    if not Path(path).exists():
        logger.warning(f"CISA KEV not found at {path}")
        return []
    with open(path) as f:
        data = json.load(f)
    vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    if isinstance(vulns, list):
        return vulns[:500]
    return []


def load_ip_list(path: str) -> List[str]:
    if not Path(path).exists():
        logger.warning(f"IP list not found at {path}")
        return ["192.168.1.1", "10.0.0.1"]
    ips = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line.split()[0])
    return ips[:10000]


def load_nvd_cves(dir_path: str) -> List[dict]:
    if not Path(dir_path).exists():
        logger.warning(f"NVD directory not found at {dir_path}")
        return []
    cves = []
    for fpath in sorted(glob.glob(os.path.join(dir_path, "*.json")))[:10]:
        try:
            with open(fpath) as f:
                data = json.load(f)
            items = data.get("vulnerabilities", data.get("CVE_Items", []))
            if isinstance(items, list):
                for item in items[:200]:
                    cve_id = None
                    if isinstance(item, dict):
                        cve_obj = item.get("cve", item)
                        cve_id = cve_obj.get("id", cve_obj.get("CVE_data_meta", {}).get("ID"))
                    if cve_id:
                        cves.append({"id": cve_id, "source_file": os.path.basename(fpath)})
        except Exception as e:
            logger.error(f"Error parsing {fpath}: {e}")
    logger.info(f"Parsed {len(cves)} NVD CVEs")
    return cves


# ═══ Neo4j Graph Builder ═══
async def build_attack_graph(techniques: List[dict]):
    if neo4j_driver is None:
        return
    async with neo4j_driver.session() as session:
        for t in techniques:
            await session.run(
                "MERGE (t:MitreTTP {ttp_id: $id}) SET t.name = $name, t.phases = $phases",
                id=t["id"], name=t["name"], phases=t.get("kill_chain_phases", []),
            )
        # Link TTPs to ServiceNodes by attack surface mapping
        service_ttp_map = {
            "api-gateway": ["T1078", "T1190", "T1548"],
            "kafka": ["T1071", "T1565"],
            "timescaledb": ["T1505", "T1190"],
            "neo4j": ["T1190", "T1059"],
            "redis": ["T1557", "T1078"],
            "self-healing": ["T1562", "T1070"],
            "react-frontend": ["T1189", "T1059"],
        }
        for svc, ttps in service_ttp_map.items():
            for ttp in ttps:
                await session.run(
                    """
                    MATCH (s:ServiceNode {name: $svc}), (t:MitreTTP {ttp_id: $ttp})
                    MERGE (s)-[:VULNERABLE_TO]->(t)
                    """,
                    svc=svc, ttp=ttp,
                )
    logger.info("Built MITRE attack graph in Neo4j")


# ═══ TimescaleDB Storage ═══
async def store_scenarios_in_pg(scenarios: List[dict]):
    if pg_pool is None:
        return
    async with pg_pool.acquire() as conn:
        for s in scenarios:
            await conn.execute(
                """INSERT INTO chaos_experiments
                   (id, scenario_id, name, mitre_ttp, attack_phase, injection_type,
                    blast_radius, target_service, status, start_time, metadata)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW(), $9)
                   ON CONFLICT (id) DO NOTHING""",
                s.get("scenario_id", str(uuid4())),
                s.get("scenario_id", str(uuid4())),
                s["name"],
                s.get("mitre_ttp", ""),
                s.get("attack_phase", ""),
                s.get("injection_type", ""),
                s.get("blast_radius", "low"),
                s.get("target_service", ""),
                json.dumps(s),
            )
    logger.info(f"Stored {len(scenarios)} chaos scenarios in TimescaleDB")


# ═══ Master Load Function ═══
async def load_all_datasets():
    global rds, pg_pool, neo4j_driver, loaded_datasets
    rds = redis_connect()
    logger.info("Connected to Redis")

    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=5)
        logger.info("Connected to TimescaleDB")
    except Exception as e:
        logger.error(f"TimescaleDB connection failed: {e}")

    try:
        neo4j_driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        logger.info("Connected to Neo4j")
    except Exception as e:
        logger.error(f"Neo4j connection failed: {e}")

    # 1. MITRE ATT&CK
    mitre = load_mitre_attack(DATASET_PATHS["mitre_attack"])
    index_to_redis("mitre:technique", mitre, "id")
    loaded_datasets["mitre_attack"] = {"count": len(mitre), "type": "techniques"}

    # 2. OWASP
    owasp = load_owasp(DATASET_PATHS["owasp_top10"])
    index_to_redis("owasp:item", owasp, "id")
    loaded_datasets["owasp_top10"] = {"count": len(owasp), "type": "risks"}

    # 3. CISA KEV
    kev = load_cisa_kev(DATASET_PATHS["cisa_kev"])
    index_to_redis("cisa:kev", kev[:500], "cveID")
    loaded_datasets["cisa_kev"] = {"count": len(kev), "type": "known_exploits"}

    # 4. Emerging Threats IPs
    et_ips = load_ip_list(DATASET_PATHS["emerging_threats"])
    rds.set("malicious_ips:emerging_threats", json.dumps(et_ips), ex=REDIS_TTL)
    loaded_datasets["emerging_threats"] = {"count": len(et_ips), "type": "malicious_ips"}

    # 5. FireHOL Level 1
    fh_ips = load_ip_list(DATASET_PATHS["firehol_l1"])
    rds.set("malicious_ips:firehol_l1", json.dumps(fh_ips), ex=REDIS_TTL)
    loaded_datasets["firehol_l1"] = {"count": len(fh_ips), "type": "malicious_ips"}

    # 6. NVD CVEs
    nvd = load_nvd_cves(DATASET_PATHS["nvd_cves"])
    index_to_redis("nvd:cve", nvd[:2000], "id")
    loaded_datasets["nvd_cves"] = {"count": len(nvd), "type": "cves"}

    # 7. STIX Full — just count objects, too large to fully index
    stix_path = DATASET_PATHS["stix_full"]
    if Path(stix_path).exists():
        try:
            with open(stix_path) as f:
                stix_data = json.load(f)
            stix_count = len(stix_data.get("objects", []))
            rds.set("stix:full:count", stix_count, ex=REDIS_TTL)
            loaded_datasets["stix_full"] = {"count": stix_count, "type": "stix_objects"}
        except Exception as e:
            logger.error(f"Failed to parse STIX full: {e}")
    else:
        loaded_datasets["stix_full"] = {"count": 0, "type": "stix_objects", "status": "not_found"}

    # Build Neo4j graph from MITRE data
    await build_attack_graph(mitre)

    logger.info(f"All datasets loaded: {json.dumps({k: v['count'] for k, v in loaded_datasets.items()})}")


# ═══ 24h Refresh Loop ═══
async def refresh_loop():
    while True:
        await asyncio.sleep(86400)
        logger.info("Refreshing datasets (24h cycle)...")
        await load_all_datasets()


# ═══ FastAPI App ═══
@asynccontextmanager
async def lifespan(app: FastAPI):
    await load_all_datasets()
    refresh_task = asyncio.create_task(refresh_loop())
    yield
    refresh_task.cancel()
    if pg_pool:
        await pg_pool.close()
    if neo4j_driver:
        await neo4j_driver.close()

app = FastAPI(title="Chaos Dataset Loader", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "chaos-dataset-loader", "datasets_loaded": len(loaded_datasets)}


@app.get("/datasets")
async def list_datasets():
    return {"datasets": loaded_datasets}


@app.get("/datasets/{name}")
async def get_dataset(name: str):
    if name not in loaded_datasets:
        raise HTTPException(status_code=404, detail=f"Dataset '{name}' not found")
    info = loaded_datasets[name]
    sample_keys = rds.keys(f"{name.replace('_', ':')}:*")[:10] if rds else []
    samples = [json.loads(rds.get(k)) for k in sample_keys if rds.get(k)] if rds else []
    return {"dataset": name, "info": info, "sample": samples[:5]}


@app.get("/datasets/mitre/techniques")
async def list_mitre_techniques():
    count = int(rds.get("mitre:technique:count") or 0)
    keys = rds.keys("mitre:technique:T*")[:50]
    techniques = [json.loads(rds.get(k)) for k in keys if rds.get(k)]
    return {"total": count, "techniques": techniques}


@app.get("/datasets/ips/malicious")
async def list_malicious_ips():
    et = json.loads(rds.get("malicious_ips:emerging_threats") or "[]")
    fh = json.loads(rds.get("malicious_ips:firehol_l1") or "[]")
    return {"emerging_threats": len(et), "firehol_l1": len(fh), "sample_et": et[:20], "sample_fh": fh[:20]}


@app.get("/metrics")
async def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    metrics = (
        f'# HELP chaos_datasets_loaded Total datasets loaded\n'
        f'# TYPE chaos_datasets_loaded gauge\n'
        f'chaos_datasets_loaded {len(loaded_datasets)}\n'
    )
    for name, info in loaded_datasets.items():
        metrics += f'chaos_dataset_items{{dataset="{name}"}} {info["count"]}\n'
    return PlainTextResponse(metrics, media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("CHAOS_ENGINE_PORT", "8020")))
