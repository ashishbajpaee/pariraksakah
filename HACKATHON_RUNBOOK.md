# Hackathon Runbook

## Goal

Present the platform as a unified cyber defense command center with three strong live stories:

1. Threat detection and monitoring
2. Phishing analysis and escalation
3. Incident response and remediation

Keep the dashboard as the hero screen. Use the Innovations page as the closing vision.

## Pre-Demo Checklist

1. Start the stack:

```bash
docker compose up -d --build
```

2. Verify the essentials:

- Frontend: `http://localhost:3000`
- Gateway health: `http://localhost:8080/health`
- Gateway readiness: `http://localhost:8080/ready`

3. Sign in with a known demo user:

- `admin / admin123`
- `analyst / analyst123`

4. Open the dashboard and confirm:

- service health cards are visible
- alert feed is visible
- login succeeded and protected pages are accessible

5. Optional background activity:

```bash
node scripts/live_event_feeder.js
```

## 2-Minute Judge Script

1. "This is our AI cyber defense command center. It brings threat detection, phishing defense, and automated response into one operating surface."
2. Point to service health, live metrics, and alerts on the dashboard.
3. Run `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-ThreatWave.ps1`.
4. "We are injecting a repeatable threat burst. The platform correlates events, updates monitoring, and surfaces alert activity in seconds."
5. Run `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-AnonymousPhishing.ps1`.
6. "Now we move from infrastructure threats to social engineering. The system analyzes the lure, the URL, and supporting attacker signals, then escalates the case."
7. Run `powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-IncidentResponse.ps1`.
8. "This creates a high-priority incident and launches an orchestration path with auditability and remediation steps."
9. Open the Innovations page.
10. "These modules show how the same platform extends into biometric trust, cognitive defense, self-healing infrastructure, and post-quantum readiness."

## 5-Minute Expanded Script

1. Start on login and position the product as a unified SOC platform.
2. Show the dashboard and explain the health cards, MITRE coverage, and live alert stream.
3. Run `Invoke-ThreatWave.ps1` and narrate detection, campaign linkage, and visibility.
4. Open Threat Hunting and explain that it is a guided analyst workspace for campaign interpretation after detection.
5. Run `Invoke-AnonymousPhishing.ps1` and explain layered phishing and social-engineering analysis.
6. Open Incident Response and show incident creation, playbook activity, and audit evidence.
7. Close on Innovations and call out Bio-Auth as the featured differentiator.

## Fallback Plan

- If a noncritical page is slow, stay on the dashboard and continue the story from the Demo Console results.
- If the live alert feed is quiet, run `Invoke-ThreatWave.ps1` again.
- If incident data takes a moment to load, describe the orchestration while the audit chain refreshes.
- If one innovation service is degraded, use it as evidence that the platform exposes operational status instead of hiding failure.

## Final Advice

- Lead with what is live.
- Describe supporting modules honestly as innovation extensions.
- Keep the story moving; judges care more about confidence and flow than exhaustive technical depth.
