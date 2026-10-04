# Deployment Safety & Sandbox Guardrails

## 1. Sandbox Isolation

The remediation sandbox isolates runtime actions from production infrastructure:

- Typed action execution handlers with strict input sanitization.
- No direct shell execution or raw subprocess invocations.
- No raw secrets, credentials, or keys passed to the LLM or captured in traces.
- Fault deactivation and restoration executed via simulation providers.

## 2. Code Remediation Safety

For `CODE_PATCH` actions:

- Isolated branch creation: `aegis/remediation/{incident_id}/{remediation_id}`.
- Patch diff validation rejects credential patterns, keys, tokens, or changes to security and migration policies.
- Pull request workflows instead of direct merges to protected branches.

## 3. Post-Deployment Telemetry Verification

Following execution, the `PostRemediationValidator` probes target health endpoints and queries telemetry signals. If metrics do not improve or regressions occur, the execution is marked `FAILED` and an automated rollback is invoked according to policy.
