# Production Hardening Checklist & Readiness

## 1. Production Readiness Checklist

- [x] **Authentication & RBAC**: JWT Bearer validation with strict role mappings (`OWNER`, `ADMIN`, `ENGINEER`, `VIEWER`).
- [x] **Tenant Isolation**: Schema-enforced multi-tenancy on all PostgreSQL records.
- [x] **Input / Output Firewall**: Mandatory `llmfirewall-core` gate on prompts and completions.
- [x] **Zero Arbitrary Shell**: Completely prohibited runtime execution paths.
- [x] **Preflight & Dry-Run**: Validated target reachability before changes.
- [x] **Automated Rollback**: Pre-defined rollback plans for high-risk operations.
- [x] **SLO & Error Budgeting**: Continuous burn rate evaluation.
- [x] **Kill Switch & Freeze**: Instantaneous administrative circuit breaking.
- [x] **Immutability of Audit**: Append-only security audit trail.
- [x] **Readiness Probes**: Deep health checks covering Postgres, Redis, MinIO, Firewall, Sandbox, and Autonomy runtime.
