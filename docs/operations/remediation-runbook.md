# Remediation Operator Runbook

## 1. Inspecting Incident Proposals

To view proposals for an active incident:

```bash
curl -X GET "http://localhost:8000/api/v1/remediations" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: ENGINEER"
```

## 2. Running Preflight Verification

Verify target reachability, schema adherence, and hash integrity without mutating state:

```bash
curl -X POST "http://localhost:8000/api/v1/remediations/<REMEDIATION_ID>/preflight" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: ENGINEER"
```

## 3. Human Approval & Rejection

Approvals require an authorized on-call principal:

```bash
# Approve
curl -X POST "http://localhost:8000/api/v1/remediations/<REMEDIATION_ID>/approve" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-id: <APPROVER_ID>" \
  -H "x-user-roles: OWNER" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Verified telemetry and root cause; approving config tweak."}'

# Reject
curl -X POST "http://localhost:8000/api/v1/remediations/<REMEDIATION_ID>/reject" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-id: <APPROVER_ID>" \
  -H "x-user-roles: OWNER" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Change window is closed for scheduled maintenance."}'
```

## 4. Triggering Remediation Execution

```bash
curl -X POST "http://localhost:8000/api/v1/remediations/<REMEDIATION_ID>/execute" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: ENGINEER"
```

## 5. Manual Emergency Rollback

If telemetry degrades after an execution, trigger immediate rollback:

```bash
curl -X POST "http://localhost:8000/api/v1/remediations/<REMEDIATION_ID>/rollback" \
  -H "x-organization-id: <ORG_ID>" \
  -H "x-user-roles: OWNER"
```
