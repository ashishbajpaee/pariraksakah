# CyberShield-X — Demo Guide

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for frontend dev)
- Go 1.21+ (for gateway dev)
- Python 3.11+ (for ML services)

### 1. Start Infrastructure
```bash
cd cybershield-x
docker-compose up -d kafka-1 kafka-2 kafka-3 timescaledb neo4j redis
```

### 2. Start All Services
```bash
docker-compose up -d --build
```

### 3. Access the Platform
| Component          | URL                            |
|--------------------|--------------------------------|
| **SOC Dashboard**  | http://localhost:3000           |
| **API Gateway**    | http://localhost:8000           |
| **Prometheus**     | http://localhost:9090           |
| **Grafana**        | http://localhost:3001           |
| **Neo4j Browser**  | http://localhost:7474           |

### 4. Run Demo Simulator
```bash
python scripts/demo_simulator.py
```

### 5. Hackathon script-driven demo flow

After signing in on the dashboard with `admin / admin123`, run the scenario scripts from PowerShell in the repository root.

- `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-ThreatWave.ps1`
- `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-AnonymousPhishing.ps1`
- `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-IncidentResponse.ps1`

Optional supporting injectors:

- `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-MalwareBurst.ps1`
- `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-RansomwareScenario.ps1`

These scripts call the live gateway routes directly and are deterministic enough for repeatable judge demos.

Use [HACKATHON_RUNBOOK.md](./HACKATHON_RUNBOOK.md) for the fastest startup checklist, judge pitch sequence, and fallback plan.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     SOC Dashboard (React)                     │
│            Port 3000 — 4 Pages, Dark Theme, WebSocket        │
├──────────────────────────────────────────────────────────────┤
│                     API Gateway (Go/Chi)                      │
│         Port 8000 — JWT, Rate Limit, Reverse Proxy           │
├──────────┬───────────┬───────────┬───────────┬───────────────┤
│ Threat   │ Access    │ Anti-     │ Incident  │ Bio-Auth      │
│ Detection│ Control   │ Phishing  │ Response  │ (ECG+Keys)    │
│ :8001    │ :8002     │ :8003     │ :8004     │ :8005         │
├──────────┼───────────┼───────────┼───────────┼───────────────┤
│ Swarm    │ Cognitive │ Self-     │ Satellite │               │
│ Agent    │ Firewall  │ Healing   │ Link      │               │
│ :8006    │ :8007     │ :8008     │ :8009     │               │
├──────────┴───────────┴───────────┴───────────┴───────────────┤
│  Kafka (3-broker)  │  TimescaleDB  │  Neo4j  │  Redis       │
└──────────────────────────────────────────────────────────────┘
```

---

## 8 Breakthrough Innovations

### 1. Autonomous Swarm Defense (P12)
**What**: 128+ AI agents with 5 roles (scout, sentinel, hunter, healer, analyst) operating via Byzantine-fault-tolerant consensus.
**Demo**: Observe swarm agent count, consensus latency, and reputation scores on the Innovations page.

### 2. Dream-State Hunting (P13)
**What**: Off-peak deep analysis that retroactively scans historical events against new threat intel and amplifies weak signals.
**Demo**: Check morning briefing reports showing overnight findings.

### 3. Bio-Cyber Fusion Authentication (P10)
**What**: ECG biometric + keystroke dynamics fused via Siamese network for continuous operator authentication.
**Demo**: View enrolled operators, fusion scores, and false reject rates.

### 4. Ephemeral Infrastructure (P11)
**What**: Self-rotating pods (4h), network segments (1h), secrets (30min) with integrity attestation and canary tokens.
**Demo**: Monitor rotation counts and canary interaction alerts.

### 5. Cognitive Firewall (P12)
**What**: HMM-based Theory of Mind predicts attacker intent along the kill chain, auto-generating firewall rules.
**Demo**: View tracked IPs, honeypot redirects, and prediction accuracy.

### 6. Self-Healing Code DNA (P14)
**What**: Rust genome registry with SHA-256 artifact hashing, automatic mutation detection and healing.
**Demo**: Check mutation count and auto-healing success rate.

### 7. Satellite Integrity Chain (P15)
**What**: GPS-timestamped tamper-evident chain with nanosecond accuracy for evidence integrity.
**Demo**: View chain length and verification status.

### 8. Post-Quantum Cryptography (P06)
**What**: CRYSTALS-Kyber-1024 key encapsulation + Dilithium3 signatures + Ed25519 JWT.
**Demo**: Check key exchange throughput and active secure sessions.

---

## API Endpoints

### Public
```
GET  /health                    → Gateway health
GET  /ready                     → All services health check
GET  /metrics                   → Prometheus metrics
POST /auth/login                → Authenticate
POST /auth/token                → OAuth2 token exchange
GET  /auth/.well-known/openid-configuration → OIDC discovery
```

### Protected (requires JWT Bearer token)
```
# Threat Detection & Alerts
GET  /api/v1/threats/*          → Threat detection service
GET  /api/v1/alerts?limit=100   → Alert feed
GET  /api/v1/metrics/dashboard  → Dashboard KPIs

# Threat Hunting
POST /api/v1/threat-hunting/search → Search threats
GET  /api/v1/threat-hunting/graph  → Attack graph

# Anti-Phishing
POST /api/v1/phishing/classify  → Classify email
POST /api/v1/phishing/url       → Analyze URL

# SOAR
GET  /api/v1/soar/playbooks     → List playbooks
GET  /api/v1/soar/incidents     → List incidents
POST /api/v1/soar/incidents     → Create incident
POST /api/v1/soar/playbooks/:name/execute → Run playbook

# Bio-Auth
POST /api/v1/bio-auth/enroll/*  → Enroll biometrics
POST /api/v1/bio-auth/verify/*  → Verify biometrics

# Swarm Intelligence
GET  /api/v1/swarm/agents       → Swarm status
GET  /api/v1/swarm/consensus    → Consensus state

# Cognitive Firewall
GET  /api/v1/cognitive-firewall/threats → Active threats

# Dream State
GET  /api/v1/dream/reports      → Morning briefings

# Self-Healing
GET  /api/v1/self-healing/health → Code DNA status

# Satellite
GET  /api/v1/satellite/*        → Integrity chain

# Innovations
GET  /api/v1/innovations/status → All 8 innovations
```

### WebSocket
```
WS   /ws/events                → Real-time threat events
```

---

## Running Tests

```bash
# Integration tests
cd cybershield-x
python -m pytest tests/ -v --tb=short

# All Python tests
python -m pytest tests/ -v
```

---

## Technology Stack

| Layer              | Technology                                      |
|--------------------|-------------------------------------------------|
| Frontend           | React 18, TypeScript, Vite, TailwindCSS, Recharts, D3, Zustand |
| API Gateway        | Go 1.21, Chi, JWT, Prometheus                   |
| ML Pipeline        | PyTorch, PyTorch Geometric (GAT), HuggingFace, XGBoost, SHAP |
| Security           | Ed25519, Kyber-1024, Dilithium3, PKCE OAuth2    |
| Messaging          | Apache Kafka (3-broker, Avro)                   |
| Databases          | TimescaleDB, Neo4j, Redis                       |
| Orchestration      | Docker Compose, Kubernetes, Helm                |
| CI/CD              | GitHub Actions (8-stage pipeline)               |
| Monitoring         | Prometheus, Grafana                             |

---

## Project Structure

```
cybershield-x/
├── frontend/                  # React SOC Dashboard (P16)
├── services/
│   ├── api-gateway/           # Go API Gateway (P17)
│   ├── threat-detection/      # Python ML + Alerts (P03-P05, P13)
│   ├── access-control/        # Go Zero Trust + PQC (P06)
│   ├── anti-phishing/         # Python Phishing AI (P07-P08)
│   ├── incident-response/     # Go SOAR + Ephemeral (P09, P11, P15)
│   ├── bio-auth/              # Python Bio-Cyber Auth (P10)
│   ├── swarm-agent/           # Go Swarm + BFT (P12)
│   ├── cognitive-firewall/    # Python HMM Firewall (P12)
│   └── self-healing/          # Rust + Python Code DNA (P14)
├── ml-models/                 # ML model definitions (P04)
├── infrastructure/            # K8s manifests, Prometheus (P02)
├── scripts/                   # Dataset generators, demo simulator
├── tests/                     # Integration tests
├── datasets/                  # Avro schemas
├── docker-compose.yml         # Full stack orchestration (P01)
└── .github/workflows/         # CI/CD pipeline (P02)
```
