# Remediation Security, Approval & Trust Boundaries

## 1. Approval Hash Binding

Human approval does not approve abstract intent; it deterministically binds to the exact remediation proposal contents:

- Actions, targets, and parameters
- Environment and affected services
- Validation plan criteria
- Rollback strategy and parameters

Any modification to any field recomputes a different SHA256 digest, invalidating any pending or previously granted approvals.

## 2. Separation of Duties

To protect against privilege escalation and unilateral change injection:

- `author_id != approver_id`: An engineer proposing a remediation cannot approve it.
- Role-based capabilities require `REMEDIATION_APPROVE` permission (assigned to `OWNER` and `ADMIN` roles).
- `VIEWER` roles hold read-only visibility into proposals, executions, and audit records.

## 3. Defense-in-Depth Execution Chain

No execution path can bypass the security chain:

```text
LLM Proposal
    ↓
Action Registry Schema Validation
    ↓
Risk Engine Evaluation
    ↓
Policy Engine Check
    ↓
LLM Firewall Tool Validation
    ↓
Human Review & Hash Verification
    ↓
Preflight Target Validation
    ↓
Sandbox Runtime Execution
    ↓
Post-Remediation Telemetry Validation
```
