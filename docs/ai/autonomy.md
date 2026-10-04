# Bounded Autonomy Governance & Operational Learning

## 1. Operational Learning Workflow

When an autonomous remediation succeeds and telemetrically validates:
1. An `IncidentLearningRecord` is recorded.
2. The resolution pattern is submitted as a reviewable runbook proposal.
3. Upon administrative verification, it promotes to operational knowledge in pgvector.

**Invariant**: AEGIS never alters foundation model weights, security policies, or permissions autonomously.

## 2. Emergency Controls & Kill Switch

```bash
# Disable all autonomy (Emergency Stop)
curl -X POST "http://localhost:8000/api/v1/autonomy/kill-switch/disable" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: OWNER"

# Restore autonomy
curl -X POST "http://localhost:8000/api/v1/autonomy/kill-switch/enable" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: OWNER"

# Toggle change freeze
curl -X POST "http://localhost:8000/api/v1/autonomy/change-freeze?enabled=true" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: OWNER"
```
