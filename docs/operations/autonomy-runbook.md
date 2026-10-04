# Autonomy Operator Runbook

## 1. Inspecting Autonomy Status

```bash
curl -X GET "http://localhost:8000/api/v1/autonomy/status" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: ENGINEER"
```

## 2. Triggering an Autonomous Reliability Agent Run

```bash
curl -X POST "http://localhost:8000/api/v1/autonomy/incidents/<INCIDENT_ID>/run-agent" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: ENGINEER"
```

## 3. Running Continuous Evaluation Benchmarks

```bash
curl -X POST "http://localhost:8000/api/v1/autonomy/evaluations/run" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: OWNER"
```

## 4. Emergency Autonomy Halt

```bash
curl -X POST "http://localhost:8000/api/v1/autonomy/kill-switch/disable" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: OWNER"
```
