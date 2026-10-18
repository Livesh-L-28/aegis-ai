# AEGIS AI — Code Review Engine Release Gate Checklist

This checklist must be executed and signed off prior to publishing or deploying the Repository Intelligence & AI Code Review Engine.

---

## 1. Automated Quality & Static Verification
- [x] **Full Pytest Suite**: Run `uv run pytest tests/`. Verified: **147 passed**, 0 failed, 1 warning (deprecation).
- [x] **Lint & Style Check**: Run `uv run ruff check .`. Verified: **All checks passed!** (0 errors).
- [x] **Strict Static Typing**: Run `uv run mypy --explicit-package-bases apps packages tests`. Verified: **Success: no issues found in 212 source files**.
- [x] **Alembic Migration Head**: Run `uv run alembic heads`. Verified: **`0006_code_review_engine (head)`**.
- [x] **CLI Smoke Test**: Run `uv run python -m packages.review.cli --help`. Verified: Output matches command specification.
- [x] **Recruiter Demo Execution**: Run `uv run python scripts/demo_review_engine.py`. Verified: All 5 stages pass cleanly.

---

## 2. Security & Policy Verification
- [x] **Path Traversal Containment (SEC-01)**:
  - Validated `validate_contained_path` strictly enforces `resolved_target.is_relative_to(resolved_root)`.
  - Rejects absolute paths (`/etc/passwd`), `../` traversal, symlink escapes, and Windows-style path separators.
  - External file contents never enter analyzers, AI prompts, or logs.
- [x] **Timeout & Resource Isolation (RES-01)**:
  - Custom adapters and external subprocesses run in isolated sessions (`start_new_session=True`).
  - Upon timeout expiration, `os.killpg(SIGKILL)` terminates the process group.
  - Caller latency is bounded, and no worker processes leak.
- [x] **Webhook Secret Fail-Closed Behavior (SEC-02)**:
  - In production (`ENVIRONMENT=production` or `AEGIS_ENV=production`), missing or default secrets raise `WebhookSecurityError`.
  - Signature validation executes prior to payload deserialization, event routing, or database operations.
  - Invalid signatures return HTTP 401/500 without processing.
- [x] **Cooperative Cancellation Immutability (RES-02)**:
  - Review engine checks cooperative cancellation tokens between analysis stages.
  - Cancelled reviews halt immediately and transition state immutably to `CANCELLED`.
  - Background workers cannot overwrite `CANCELLED` with `COMPLETED` or `FAILED`.
- [x] **Tenant Scoping & RBAC**:
  - All review session queries filter by `organization_id`.
  - Cross-tenant review session IDs return HTTP 404 without data disclosure.
  - Triggering reviews requires `Role.ADMIN` or `Role.SECURITY_ENGINEER` (`PROJECT_WRITE`).

---

## 3. Database & Migration Review
- [x] **Migration Script**: `apps/api/app/db/migrations/versions/0006_code_review_engine.py` reviewed.
- [x] **Foreign Keys & Indices**:
  - `review_sessions`: Indexed on `organization_id`, `created_at`, `status`.
  - `review_findings`: Foreign key `review_id` with `ondelete="CASCADE"`, indexed on `severity`, `category`, `rule_id`.
- [x] **Reversibility**: Both `upgrade()` and `downgrade()` functions implemented and verified.
- [x] **Zero Production Data Mutation**: Migrations tested exclusively against disposable test environments.

---

## 4. Operational Boundaries & Deployment Profiles
- [x] **Local CLI Profile**: Read-only, operates directly on local git working tree. External tools and AI disabled by default.
- [x] **Trusted CI Profile**: Runs in automated pipeline with `--format json` and `--severity-threshold ERROR`.
- [x] **Multi-Tenant SaaS Profile**:
  - API protected by JWT authentication and RBAC.
  - Webhooks verified via constant-time HMAC-SHA256 and delivery ID deduplication.
  - In-process AST checks execute with zero subprocess overhead.
- [x] **Untrusted Repository Execution Policy**:
  - Bare-metal subprocess execution is **PROHIBITED** for untrusted user-submitted repositories with arbitrary build tools.
  - Mandatory requirement: Untrusted repositories requiring custom linters must run inside an ephemeral container (Docker/gVisor/Firecracker) with dropped capabilities and no network access.

---

## 5. Artifact & Repository Integrity
- [x] **Protected Repository Integrity**: `/Users/livesh/AEGIS-Framework` verified clean (0 modifications, untouched).
- [x] **Untracked User Assets**: `render_schema.json` preserved intact (SHA-256 verified).
- [x] **Non-Destructive Git State**: Zero destructive git commands (`git reset`, `git clean`) executed.
- [x] **No Premature Release Actions**: Zero git commits, git tags, git pushes, or package publications made.

---

## 6. Release Sign-Off
- **Status**: **READY FOR MANUAL RELEASE REVIEW**
- **Date**: October 18, 2026
- **Target Version**: `1.0.0-rc1`
- **Release Gate Verdict**: PASS WITH OPERATIONAL CONTAINER LIMITATION
