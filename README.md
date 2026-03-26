# CyberShield-X

**National-Grade AI-Powered Cyber Defense Platform**

## Architecture

CyberShield-X is built as a cloud-native microservices platform with 4 core pillars and 8 breakthrough innovations.

### Core Pillars
1. **AI Threat Detection Engine (ATDE)** — Real-time GNN-based threat detection with UEBA
2. **Quantum-Safe Access Control** — Zero Trust + Post-Quantum Cryptography (CRYSTALS-Kyber/Dilithium)
3. **AI Anti-Phishing Engine** — Transformer-based phishing detection + URL detonation + deepfake voice detection
4. **Automated Incident Response** — SOAR engine with adaptive playbooks + AI investigation

### Breakthrough Innovations
1. Bio-Cyber Fusion Authentication (BCFA)
2. Psychographic Attack Prediction Engine (PAPE)
3. Ephemeral Infrastructure with Proof-of-Freshness
4. Swarm Intelligence Defense Network
5. Temporal Dream-State Threat Hunting (TDSTH)
6. Self-Healing Code DNA (SHCD)
7. Cognitive Firewall with Attacker Theory-of-Mind
8. Satellite-Based Cryptographic Integrity Anchoring

## Tech Stack
| Component | Technology |
|-----------|-----------|
| Threat Detection | Python, PyTorch, PyTorch Geometric, FastAPI |
| Access Control | Go, CRYSTALS-Kyber, OPA |
| Anti-Phishing | Python, HuggingFace Transformers, Playwright |
| Incident Response | Go, YAML Playbooks |
| Self-Healing | Rust, eBPF |
| Frontend | React 18, TypeScript, Vite, TailwindCSS, D3.js |
| Messaging | Apache Kafka, Apache Flink |
| Databases | TimescaleDB, Neo4j, Redis |
| Orchestration | Kubernetes, Helm, Terraform |
| CI/CD | GitHub Actions |
| Observability | Prometheus, Grafana |

## Quick Start

```bash
# Clone the repo
git clone https://github.com/your-org/cybershield-x.git
cd cybershield-x

# Copy environment file
cp .env.example .env
# Edit .env with your secrets

# Start all services
docker-compose up -d

# Verify
curl http://localhost:8080/health
```

## Project Structure
```
cybershield-x/
├── services/
│   ├── threat-detection/     # Python — ML-based ATDE engine
│   ├── access-control/       # Go    — Zero Trust + PQC auth
│   ├── anti-phishing/        # Python — NLP phishing detection
│   ├── incident-response/    # Go    — SOAR orchestration engine
│   ├── bio-auth/             # Python — Bio-Cyber Fusion Auth
│   ├── swarm-agent/          # Go    — Lightweight swarm node
│   ├── cognitive-firewall/   # Python — Attacker ToM prediction
│   ├── self-healing/         # Rust  — Code DNA integrity monitor
│   └── api-gateway/          # Go    — API gateway
├── frontend/                 # React + TypeScript SOC dashboard
├── ml-models/                # PyTorch model training pipelines
├── datasets/                 # Synthetic + real dataset storage
├── infrastructure/
│   ├── kubernetes/           # K8s manifests
│   ├── terraform/            # AWS + Azure IaC
│   └── helm/                 # Helm charts per service
├── scripts/                  # Dev, build, deploy scripts
└── docs/                     # Architecture docs
```

## Development

See individual service READMEs for setup instructions.

### Dev Baseline (Windows/Linux)

- Python: `3.11+` (project currently tested on newer versions as well)
- Node.js: `20 LTS` (or newer compatible runtime)
- Go: `1.21+`
- Rust: stable toolchain via `rustup` (`cargo` required for `services/self-healing` builds)

### One-Command Local Bootstrap

Run this once from repository root:

```bash
python scripts/bootstrap_dev.py
```

This installs test-only Python dependencies from `requirements-test.txt`, installs frontend dependencies when `npm` is available, and checks whether `cargo` is installed.

### Rust Toolchain Setup

- Windows (PowerShell):

```powershell
winget install Rustlang.Rustup
rustup default stable
```

- Linux/macOS:

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
rustup default stable
```

## Share With A Friend: Fresh Machine Setup + Seed Data

Use this when someone else wants to run the full stack quickly and see non-empty dashboards.

### 1. Prerequisites

- Docker Desktop (with Docker Compose v2)
- Node.js 20+ (for running the event feeder script)
- Git

### 2. Clone and start all services

```bash
git clone https://github.com/PankajKumar17/pariraksakah.git
cd pariraksakah
docker compose up -d --build
```

### 3. Verify core endpoints

Open these URLs in browser:

- Dashboard: http://localhost:3000
- API Gateway health: http://localhost:8080/health
- Gateway readiness: http://localhost:8080/ready

### 4. Login credentials

Default local users from access-control service:

- admin / admin123
- analyst / analyst123
- viewer / viewer123

### 5. Seed demo threat data (one-time)

From repository root:

```bash
node scripts/live_event_feeder.js --once
```

This sends a burst of threat events through the gateway so charts and alert lists populate.

### 6. Keep data flowing live (optional)

Run in a second terminal:

```bash
node scripts/live_event_feeder.js
```

Optional tuning:

- `API_BASE` (default `http://localhost:8080`)
- `DEMO_USER` / `DEMO_PASS` (default `admin` / `admin123`)
- `FEED_INTERVAL_MS` (default `8000`)

Example:

```bash
API_BASE=http://localhost:8080 FEED_INTERVAL_MS=3000 node scripts/live_event_feeder.js
```

### 7. If the frontend page is stale

```bash
docker compose restart frontend
```

If needed, restart gateway too:

```bash
docker compose restart api-gateway
```

### 8. Stop everything

```bash
docker compose down
```

## Hackathon Demo Flow

Use this flow when presenting to judges so the strongest end-to-end stories are one click away.

### 1. Start the full stack

```bash
docker compose up -d --build
```

### 2. Open the platform

- Dashboard: http://localhost:3000
- Gateway health: http://localhost:8080/health
- Gateway readiness: http://localhost:8080/ready

### 3. Sign in with a demo user

- `admin / admin123`
- `analyst / analyst123`

### 4. Run the demo scripts from PowerShell

From repository root, use the scenario injectors instead of the dashboard UI:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-ThreatWave.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-AnonymousPhishing.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-IncidentResponse.ps1
```

Additional injectors:

- `.\scripts\Invoke-MalwareBurst.ps1`
- `.\scripts\Invoke-RansomwareScenario.ps1`

These scripts log in, call the real backend routes, and leave visible results in the dashboard and incidents board.

### 5. Optional background feed

If you want the alert stream to continue between judge conversations:

```bash
node scripts/live_event_feeder.js
```

### 6. Suggested pitch order

1. Dashboard overview and service health
2. `Invoke-ThreatWave.ps1` for live alerts and MITRE coverage
3. `Invoke-AnonymousPhishing.ps1` for social-engineering defense
4. `Invoke-IncidentResponse.ps1` for automated remediation
5. Innovations page for the broader platform vision

For a judge-ready checklist and short presentation script, see [HACKATHON_RUNBOOK.md](./HACKATHON_RUNBOOK.md).


## License

Proprietary — All rights reserved.
