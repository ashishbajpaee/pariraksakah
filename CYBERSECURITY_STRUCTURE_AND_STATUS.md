# Pariraksakah Project Structure and Status

Updated: 2026-03-24

## 1) Project Structure (High-Level)

```text
abc/├── frontend/                     # React + TypeScript SOC dashboard (Dashboard, Threat Hunting, Innovations, Incidents)├── services/│   ├── api-gateway/             # Go gateway (routing, auth middleware, health aggregation)│   ├── threat-detection/        # Python threat detection + UEBA + recent threats API│   ├── access-control/          # Go authentication and token verification│   ├── anti-phishing/           # Python email/url phishing analysis│   ├── incident-response/       # Go SOAR-style incident + playbook execution│   ├── bio-auth/                # Python biometric service (separate module)│   ├── swarm-agent/             # Go swarm defense service (separate module)│   ├── cognitive-firewall/      # Python adaptive firewall logic (separate module)│   └── self-healing/            # Rust/Python self-healing service (separate module)├── infrastructure/│   ├── kubernetes/              # K8s manifests│   └── prometheus.yml           # Monitoring config├── ml-models/                   # Model code and training pipelines├── datasets/                    # Schemas and data assets├── scripts/                     # Demo/event generators├── tests/                       # Integration tests├── docker-compose.yml           # Full local stack orchestration└── vercel.json                  # Frontend deployment config
```

## 2) Status Against Your 4 Cyber Security Points

### A. Threat detection & real-time monitoring systems

What is made:

-   Threat detection service is implemented with rule/statistical logic and UEBA.
-   API endpoints exist for network analysis, UEBA analysis, batch analysis, recent threats, and stats.
-   Monitoring stack is present: Prometheus + Grafana.
-   Gateway health/readiness aggregation is implemented.

What is left:

-   Dashboard alert feed is still synthetic at gateway layer (`liveAlertsHandler`) instead of fully sourced from live detected incidents.
-   Event streaming pipeline from Kafka/Flink into detection outcomes is not fully represented in dashboard UX as an end-to-end live feed.
-   Production-grade alert correlation/suppression tuning and persistent detection history are still limited (mostly in-memory behavior in core services).

Steps

Phase 1: Live Alert Feed First (MVP)Replace synthetic gateway alert generation with live upstream data while keeping the current response shape stable for frontend compatibility.Add explicit live/degraded metadata in alert payloads so the UI never silently shows synthetic-style data.Add a gateway feature flag to switch between old/new handler during rollout.Phase 2: Persistence and State Reliability (depends on Phase 1)Persist detections/alerts in TimescaleDB so container restarts do not wipe operational history.Apply retention + index strategy for fast recent alerts and historical lookups.Bound or persist current in-memory state to remove growth/restart risks.Phase 3: End-to-End Streaming Visibility (parallel with late Phase 2)Add Kafka consumer-driven detection flow so dashboard updates reflect stream events, not only direct API submissions.Wire WebSocket + REST fallback to one canonical alert source so timeline and list stay consistent.Phase 4: Correlation and Suppression Quality (depends on Phases 2 and 3)Integrate deduplication/suppression into the main processing path (not utility-only side code).Add campaign/kill-chain correlation metadata to alerts for grouped investigation.Add analyst feedback loop for false-positive suppression tuning.Phase 5: Rollout Safety and Monitoring (parallel with Phase 4)Add metrics for ingestion lag, alert latency, dedup hit rate, suppression rate, and persistence failures.Run staged rollout: synthetic off in staging, then production with rollback toggle.What We Can Cover Under Point A

Remove synthetic alert feed behavior.Make dashboard truly reflect live detections.Add persistent detection history.Connect stream ingestion to dashboard UX.Improve alert quality with dedup/suppression/correlation.Add operational SLOs and safe rollout controls.

### B. Secure access & advanced encryption frameworks

What is made:

-   Access control service supports login, token verify, logout, and user roles.
-   JWT-based authentication and gateway protected routes are in place.
-   Passwords are hashed before comparison in service logic.

What is left:

-   "Advanced encryption frameworks" (especially post-quantum crypto claims from docs) are not fully implemented as real cryptographic flow in runtime auth.
-   No full RBAC/ABAC policy engine integration exposed in active flow.
-   No enterprise identity federation (OIDC provider integration with external IdP, key rotation/JWKS lifecycle hardening) at production depth.

### C. Phishing prevention & anti-social engineering tools

What is made:

-   Anti-phishing service supports email and URL analysis endpoints.
-   Service tracks analyzed/blocked counters and exposes stats.
-   URL risk and email classification flows are available through gateway public endpoints.

What is left:

-   Deepfake/voice and broader social-engineering modules are only partially represented compared to platform claims.
-   Threat intel enrichment and sandbox detonation are not fully exposed as end-to-end validated pipeline outputs in dashboard.
-   Model lifecycle (continuous retraining/feedback loop) is not yet surfaced as operational workflow.

### D. Incident response & automated remediation platforms

What is made:

-   Incident response service implements incident creation/list/get and playbook execution.
-   Automatic playbook triggering exists for high/critical incidents.
-   Multiple built-in playbooks are available with step-by-step execution state.

What is left:

-   Playbook actions are simulated (sleep + status updates) rather than fully integrated with real EDR/firewall/ticketing systems.
-   End-to-end closed-loop remediation evidence (audit trail + rollback + external integrations) remains incomplete.
-   Production-grade persistence/queueing/retry strategy for response orchestration needs hardening.

## 3) Overall Completion Snapshot

-   Core platform skeleton: Done
-   Functional service endpoints for all 4 points: Mostly done
-   End-to-end production-grade automation/integration depth: Partially done

In short: the project is strong as a working prototype/demo platform, with major foundational components implemented. The main work left is converting synthetic/simulated parts into fully integrated, production-grade cyber operations workflows.

## 4) Recommended Next Implementation Priorities

1.  Replace synthetic gateway alerts with real alerts from detection/incident stores.
2.  Add persistent event + alert storage and query APIs for historical monitoring.
3.  Upgrade auth from basic JWT flow to hardened key management and policy enforcement.
4.  Integrate real remediation connectors (EDR, SIEM, firewall, IAM, ticketing).
5.  Expand anti-social engineering scope (voice/deepfake + campaign simulation + analyst feedback loop).