# Programmatic AI Policy Engine

## Overview
The `AIPolicyEngine` (`packages/security/policy.py`) enforces deterministic, code-level governance rules on AI operations. Policies are strictly evaluated in software rather than relying on LLM prompt instructions.

## Risk Levels
AEGIS categorizes all operations into 5 discrete risk levels:

| Risk Level | Description | Phase 5 Action |
|------------|-------------|----------------|
| `READ_ONLY` | Read-only inspection of telemetry, evidence, metadata, topology | **Permitted** |
| `LOW` | Benign sandbox operations | Boundary Established |
| `MEDIUM` | Operations requiring approval gates | Approval Boundary Established |
| `HIGH` | Write operations, container restarts, config mutations | **Blocked** |
| `CRITICAL` | Cluster reconfigurations, git commits, deployments | **Blocked** |

## Data Classification
Contexts and prompts are classified into data tiers:
1. `PUBLIC`: Generic architecture details and non-sensitive error summaries.
2. `INTERNAL`: Internal topology, service names, and runbook content.
3. `SENSITIVE`: Customer identifiers, PII, and sensitive telemetry. Permitted only on authorized, secure providers.
4. `SECRET`: Passwords, Bearer tokens, private keys. **Strictly blocked** if unredacted.

## Tenant Model Whitelisting
Tenants can define policies stored in PostgreSQL (`ai_policies`):
- `allowed_models`: Whitelist of approved foundation models.
- `allowed_providers_for_sensitive`: Approved execution providers for sensitive data tiers.
- `max_context_tokens`: Upper bound on prompt token allowance.
