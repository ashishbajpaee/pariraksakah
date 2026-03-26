# Security Chaos Engineering — Test & Validation Plan

## 1. Unit Tests

### Chaos Experiment Engine (Python)
```bash
cd services/chaos-experiment-engine
pytest tests/ -v
```

| Test | Description | Assertion |
|------|------------|-----------|
| `test_start_experiment` | POST /experiments/start returns 200 | experiment_id is UUID, status is "running" |
| `test_dry_run` | POST /experiments/dry-run | No actual injection called, status completes |
| `test_kill_all` | POST /chaos/kill-all | All active experiments transition to "aborted" |
| `test_abort_watcher` | Simulate health drop to 70% | Experiment auto-aborts within 10s |
| `test_hypothesis_validation` | Submit experiment with hypothesis | Hypothesis stored and returned |

### Chaos Guardrails (Go)
```bash
cd services/chaos-guardrails
go test ./... -v
```

| Test | Description | Assertion |
|------|------------|-----------|
| `TestSacredServiceBlock` | Attempt chaos on "prometheus" | Returns `approved: false` |
| `TestBudgetEnforcement` | Submit 11 experiments in dev | 11th is rejected with budget error |
| `TestHealthGateBlock` | Mock Prometheus returning 60% health | Returns `approved: false` |
| `TestHumanApprovalTimeout` | Submit HIGH blast without approval | Times out, experiment blocked |

### Defense Validator (Python)
| Test | Description | Assertion |
|------|------------|-----------|
| `test_resilience_score_calculation` | Given known inputs | Score matches manual calculation |
| `test_gap_flagging` | false_negative_rate > 0 | CRITICAL gap inserted in chaos_gaps |
| `test_scorecard_generation` | Run measure_experiment | Scorecard JSON has all required fields |

### Chaos Injection Agent (Rust)
```bash
cd services/chaos-injection-agent
cargo test
```

| Test | Description | Assertion |
|------|------------|-----------|
| `test_jwt_forgery` | Inject forged JWT | Returns injection result string |
| `test_rollback` | POST /rollback | iptables flushed, status "rolled_back" |
| `test_health` | GET /health | Returns 200 with service name |

## 2. Integration Tests

| Test | Components | Description | Expected |
|------|-----------|-------------|----------|
| Engine → Kafka | Experiment Engine, Kafka | Start experiment, verify event on `chaos.experiments` topic | Message arrives within 5s |
| Engine → Guardrails | Engine, Guardrails, Redis | Start HIGH blast experiment | Guardrails blocks without human approval |
| Engine → Agent → Rollback | Engine, Agent | Start + stop experiment | Agent rollback called, iptables flushed |
| AI → TimescaleDB | AI Intelligence, TimescaleDB | Call /gaps endpoint | Returns MITRE coverage percentage |
| Scheduler → Engine | Scheduler, Engine | Trigger hourly job manually | Experiment created in engine |

## 3. End-to-End Tests

### Full Chaos Lifecycle Test
```
1. POST /experiments/start (JWT Forgery, medium blast)
2. Verify Kafka chaos.experiments receives event
3. Verify chaos-injection-agent /inject called
4. Wait for experiment completion (30s)
5. Verify chaos.results Kafka event published
6. Verify chaos_results row in TimescaleDB
7. Verify resilience scorecard generated
8. POST /experiments/stop (verify abort works)
9. POST /chaos/kill-all (verify emergency stop)
```

### Multi-Stage Attack Chain Test
```
1. POST /chaos-ai/attack-chain
2. Verify Stage 1 (JWT Forgery) executes
3. Verify Stage 2 (Kafka Poisoning) triggers only if Stage 1 succeeds
4. Verify chain breaks when defense detects an attack
5. Verify all stages logged in chaos_audit_trail
```

## 4. Performance Tests

| Test | Metric | Target |
|------|--------|--------|
| Chaos overhead on API Gateway | Gateway p99 latency increase | < 5% |
| Kafka event throughput during chaos | Messages/second maintained | > 95% of baseline |
| TimescaleDB write latency during chaos | p99 write latency | < 500ms |
| Experiment engine startup | Cold start to ready | < 10s |
| Concurrent experiments | Run 5 experiments simultaneously | All complete without interference |

## 5. Safety Tests

| Test | Description | Target |
|------|------------|--------|
| Kill switch response time | POST /chaos/kill-all → all experiments stopped | < 5 seconds |
| Sacred service protection | Attempt chaos on Prometheus, Grafana, Schema Registry, TimescaleDB write path | 100% blocked |
| Budget enforcement | Exceed daily limit | 100% of excess experiments blocked |
| Health gate enforcement | Drop mock health to 75% | All new experiments blocked |
| Auto-abort on health drop | Health drops mid-experiment | Experiment aborts within 15s |

## 6. Rollback Tests

| Test | Description | Target |
|------|------------|--------|
| Container rollback | Kill container, verify restart | < 30 seconds |
| Network partition reversal | Inject iptables DROP, then rollback | < 30 seconds |
| Redis state restoration | Poison Redis keys, then flush | < 30 seconds |
| Kafka offset reset | Simulate lag attack, reset offsets | < 60 seconds |
| Full stack rollback | Abort GameDay mid-execution | All services healthy within 60s |

## Execution Commands

```bash
# Run all Python tests
cd services/chaos-experiment-engine && pytest tests/ -v --tb=short
cd services/chaos-scheduler && pytest tests/ -v --tb=short
cd services/chaos-ai-intelligence && pytest tests/ -v --tb=short

# Run Go tests
cd services/chaos-guardrails && go test ./... -v -race

# Run Rust tests
cd services/chaos-injection-agent && cargo test -- --nocapture

# Run integration tests (requires docker-compose up)
docker-compose exec chaos-experiment-engine pytest tests/integration/ -v

# Run safety tests
curl -X POST http://localhost:8024/approve -d '{"target_service":"prometheus","blast_radius":"low"}' | jq .approved
# Should return false

# Run kill switch test
curl -X POST http://localhost:8020/chaos/kill-all | jq .
# Should return within 5 seconds
```
