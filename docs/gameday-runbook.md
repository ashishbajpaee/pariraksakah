# GameDay Runbook — Security Chaos Engineering

## Pre-GameDay Checklist (T-24 hours)

| # | Check | Owner | Status |
|---|-------|-------|--------|
| 1 | Confirm all services healthy via Prometheus (`up == 1`) | SRE Lead | ☐ |
| 2 | Verify chaos-guardrails is running and budget available | SecOps | ☐ |
| 3 | Verify chaos-experiment-engine responds at `/health` | Platform Eng | ☐ |
| 4 | Verify chaos-injection-agent responds at `/health` | Platform Eng | ☐ |
| 5 | Confirm rollback mechanism tested (run dry-run) | SRE Lead | ☐ |
| 6 | Notify incident response team of GameDay window | IR Lead | ☐ |
| 7 | Confirm TimescaleDB backup exists (< 4 hours old) | DBA | ☐ |
| 8 | Verify Kafka topics `chaos.*` exist with correct schemas | Platform Eng | ☐ |
| 9 | Confirm Grafana chaos dashboard panels are visible | Observability | ☐ |
| 10 | Brief all participants on abort criteria and kill switch | GameDay Lead | ☐ |

## Participant Roles

| Role | Responsibility |
|------|---------------|
| **GameDay Lead** | Coordinate execution, make go/no-go decisions, trigger kill switch |
| **SRE Lead** | Monitor Prometheus/Grafana, validate health gates, execute rollbacks |
| **SecOps** | Monitor Falco alerts, validate detection coverage, track gaps |
| **Platform Eng** | Monitor chaos engine logs, troubleshoot injection agents |
| **IR Lead** | Manage incident response if real issues emerge, own comms |
| **DBA** | Monitor TimescaleDB performance, verify audit trail integrity |

## Experiment Sequence

### Phase 1: Warm-Up (30 min)
1. **Dry Run**: `POST /experiments/dry-run` — JWT Forgery scenario
2. **Low Blast**: Single container kill of `swarm-agent`, measure restart time
3. **Validation**: Confirm Prometheus metrics updating, Kafka events flowing

### Phase 2: Service-Level Chaos (60 min)
4. **JWT Token Forgery** on API Gateway (medium blast)
5. **Redis Cache Poisoning** (medium blast)
6. **Kafka Consumer Group Lag Attack** (medium blast)
7. **Falco Alert Flood** on Self-Healing Engine (medium blast)

### Phase 3: Infrastructure Chaos (45 min)
8. **TimescaleDB Connection Pool Exhaustion** (high blast — requires human approval)
9. **Network Partition** between API Gateway and Kafka (high blast)
10. **Container Kill Storm** — kill 3 random non-sacred services simultaneously

### Phase 4: APT Chain Simulation (30 min)
11. **Multi-Stage Attack Chain**: JWT Forgery → Kafka Poisoning → Redis Backdoor → TimescaleDB Exfil

## Monitoring Checkpoints

Every 15 minutes during GameDay, the SRE Lead must verify:
- [ ] All sacred services (Schema Registry, TimescaleDB write path, Prometheus, Grafana) are UP
- [ ] No service health is below 80%
- [ ] TimescaleDB write latency < 500ms
- [ ] No CRITICAL Falco alerts unrelated to chaos injection
- [ ] Kafka consumer lag < 10,000 messages

## Abort Criteria

**Immediately trigger `POST /chaos/kill-all` if ANY of these occur:**
- Any sacred service goes DOWN
- TimescaleDB write latency exceeds 2000ms
- Falco triggers a CRITICAL alert not correlated to a chaos experiment
- Any service fails to recover within 120 seconds of experiment completion
- Production traffic is impacted (if running in shared environment)
- Any participant calls "ABORT"

## Post-GameDay Analysis (T+2 hours)

1. **Collect Results**: Pull all data from `chaos_results` and `chaos_gaps` tables
2. **Generate Scorecard**: `GET /chaos-ai/gaps` for MITRE coverage report
3. **Review Gaps**: Identify all undetected injections (false negatives)
4. **Review Metrics**: Check if all 6 defense metrics met targets
5. **Document Failures**: Create tickets for every gap with severity rating
6. **Update Scenarios**: Feed results into AI module for improved future scenarios

## Lessons-Learned Template

| Category | Finding | Action Item | Owner | Due Date |
|----------|---------|------------|-------|----------|
| Detection Gap | | | | |
| Response Delay | | | | |
| Recovery Failure | | | | |
| Tooling Issue | | | | |
| Process Gap | | | | |
