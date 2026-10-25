# LogicFalcon Forward Deployment Engineering (FDE)

Forward Deployment Engineering (FDE) is a modular, secure, and deterministic operational subsystem in **LogicFalcon v0.1.4**. It extends LogicFalcon's static engineering intelligence into active, safe deployment preparation, verification, and controlled execution.

---

## Core Pillars of FDE

1. **Deterministic Repository & Deployment Discovery**:
   - Statically catalogs web frameworks (FastAPI, Flask, Django, Express, Next.js), exposed port allocations, database dependencies (PostgreSQL, MySQL, Redis, MongoDB), and Docker compose topology without executing code or mutating target systems.

2. **Non-Destructive Environmental Preflight Probes**:
   - Performs bounded checks on runtime versions (Python, Node), TCP port availability, DNS resolution, and required environment variables before any deployment step is initiated.

3. **Safe Adapters & Central Registry**:
   - Standardized, least-privilege execution interfaces:
     - `SystemAdapter`: Non-shell subprocess execution with timeout and process-group isolation.
     - `HttpAdapter`: Strict SSRF defense blocking loopback, RFC 1918, and cloud metadata IPs (`169.254.169.254`). Enforces TLS verification and payload limits (512 KB).
     - `PostgresAdapter`: Read-only query execution with SQL injection validation.
     - `DockerAdapter`: Container lifecycle management with least privilege.
     - `McpAdapter`: Model Context Protocol integration with payload scrubbing.
     - `AwsAdapter`: AWS SDK operations bounded by strict IAM and dry-run policies.

4. **Policy Gateway & Cryptographic Approvals**:
   - State-machine orchestration enforcing operation classifications:
     - `READ_ONLY`: Automated, zero-mutation checks.
     - `CONTAINED_WRITE`: Local isolated state creation (requires permission).
     - `EXTERNAL_MUTATING`: Network or infrastructure modifications (requires cryptographic approval token).
     - `DANGEROUS`: High-risk or destructive actions (fails closed unless explicitly permitted).
   - Approval tokens are SHA-256 HMAC-bound to specific mission IDs, target parameters, and operations. They cannot be replayed or altered.

5. **Postcondition Verification**:
   - Validates deployment outcomes using declarative assertions on HTTP status codes, JSON payload fields, and port bindings.

6. **Automated Root-Cause Failure Diagnosis**:
   - Correlates failed step logs, error categories, and postcondition failures into ranked diagnostic hypotheses with confidence scores and recommended remediations.

7. **Atomic Checkpointing & Redaction**:
   - Saves mission state atomically via `.tmp` swap with `0o600` file permissions. Recursively redacts credentials and tokens across all checkpoints and logs.

8. **Operational Handover Runbooks**:
   - Synthesizes clear, reproducible Markdown and JSON runbooks with sanitized commands, preflight requirements, and rollback instructions for human operators.

---

## Documentation Index

- [FDE Architecture & Security Model](architecture.md): Deep dive into adapters, DAG state machine, SSRF defense, and approval token cryptography.
- [FDE CLI Reference](cli-reference.md): Complete guide to `logicfalcon fde` CLI commands, options, outputs, and exit codes.
- [FDE SDK Reference](sdk-reference.md): Python SDK API reference, data models, and programmatic workflow examples.

---

## Quick Example

```bash
# 1. Discover repository deployment topology
logicfalcon fde inspect --repo .

# 2. Run environmental preflight probes
logicfalcon fde preflight --repo .

# 3. Generate deployment mission plan (dry-run)
logicfalcon fde plan --repo . --operation deploy --output plan.json

# 4. Generate human-readable operational runbook
logicfalcon fde runbook --mission-file plan.json --output-format markdown

# 5. Execute simulation / dry-run
logicfalcon fde run --mission-file plan.json --dry-run
```
