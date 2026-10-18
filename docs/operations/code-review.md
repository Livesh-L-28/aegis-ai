# AEGIS AI — Code Review Operations & Runbook

## 1. Local CLI Usage & CI Integration

The AEGIS AI Code Review engine can be executed directly from developer terminals or in automated CI workflows:

```bash
# Review local working tree changes in current repo
uv run python -m packages.review.cli --repo .

# Review changes against a specific base branch (e.g. main)
uv run python -m packages.review.cli --repo . --base main

# Output machine-readable JSON for CI integration
uv run python -m packages.review.cli --repo . --format json

# Fail build only on CRITICAL findings
uv run python -m packages.review.cli --repo . --severity-threshold CRITICAL

# Fail build on ERROR or CRITICAL findings (default)
uv run python -m packages.review.cli --repo . --severity-threshold ERROR

# Enable optional AI analysis and external linters
uv run python -m packages.review.cli --repo . --enable-ai --enable-tools
```

### CLI Exit Codes:
* `0`: Clean review or no findings meeting or exceeding `--severity-threshold`.
* `1`: One or more findings detected at or above `--severity-threshold` (blocks CI build).
* `2`: Execution failure, missing repository, or invalid configuration.

---

## 2. API Endpoints & RBAC Permissions

All review endpoints are exposed under `/api/v1/reviews` with tenant isolation (`organization_id`):

| Method | Endpoint | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/reviews/` | `PROJECT_WRITE` (`Role.ADMIN`, `Role.SECURITY_ENGINEER`) | Trigger an asynchronous review session on a diff or repository. |
| `GET` | `/api/v1/reviews/{review_id}` | `PROJECT_READ` (`Role.VIEWER` and above) | Query review session details, summary, and status. |
| `GET` | `/api/v1/reviews/{review_id}/findings` | `PROJECT_READ` (`Role.VIEWER` and above) | List findings for a session with optional severity/category filtering. |
| `POST` | `/api/v1/reviews/{review_id}/cancel` | `PROJECT_WRITE` (`Role.ADMIN`, `Role.SECURITY_ENGINEER`) | Cooperatively cancel an in-flight review session. |
| `POST` | `/api/v1/reviews/webhook/github` | None (Public webhook) | Receive GitHub pull request webhooks; verified via HMAC-SHA256 signature. |

---

## 3. Configuration & Environment Variables

| Variable | Default | Required in Production | Description |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | Yes (`production`) | Application environment. Triggers strict fail-closed security when set to `production`. |
| `GITHUB_WEBHOOK_SECRET` | `default-dev-secret` | Yes (in production) | Shared secret for HMAC-SHA256 GitHub webhook verification. If missing or default in production, returns HTTP 500. |
| `GITHUB_TOKEN` | None | For PR publishing | GitHub Personal Access Token or GitHub App Installation Token with PR read/write permissions. |
| `DATABASE_URL` | SQLite / Local Postgres | Yes | PostgreSQL connection string for review session and finding persistence. |

---

## 4. Operational Deployment Profiles

### Profile 1: Local Developer CLI
- **Characteristics**: Local execution with no external network calls or credentials required. Small, localized single-file test fixtures completed in approximately 2–5 ms in the observed demo runs; larger diffs and repositories may take longer.
- **Analyzers**: In-process AST security (`ast_security`). External linters and AI disabled by default.
- **Safety**: Pure read-only file access; path traversal containment protects against symlink and directory escape attacks.

### Profile 2: Trusted Enterprise CI (GitHub Actions / GitLab CI)
- **Characteristics**: Automated pipeline step analyzing pull requests before merge.
- **Configuration**:
  ```yaml
  - name: Run AEGIS AI Code Review
    run: uv run python -m packages.review.cli --repo . --base origin/main --severity-threshold ERROR
  ```
- **Safety**: Bounded subprocess timeouts (default 10s per file), exit code 1 blocks PR merge on critical/error findings.

### Profile 3: Multi-Tenant SaaS
- **Characteristics**: Centralized review service receiving webhooks and serving API requests.
- **Safety**:
  - Webhooks verified using constant-time HMAC-SHA256 before parsing payload.
  - Delivery ID deduplication prevents replay attacks.
  - Stale-head protection prevents race conditions if newer commits are pushed during analysis.
  - Queries strictly filtered by `organization_id`; cross-tenant access returns 404.

### Profile 4: Untrusted Third-Party Repositories (Mandatory Container Isolation)
- **Operational Policy**: Bare-metal subprocess execution of untrusted code or repository-controlled tools is **strictly prohibited**.
- **Requirement**: If analyzing untrusted repositories with external linters or build tools, execution must be delegated to an ephemeral container sandbox (Docker/gVisor/Firecracker) with dropped privileges, non-root user, read-only root filesystem, memory/CPU cgroups, and no network access.

---

## 5. Failure Behavior & Incident Runbook

### Issue 1: GitHub Webhook Rejections (`401 Unauthorized` or `500 Internal Server Error`)
- **Symptoms**: GitHub reports webhook delivery failures.
- **Causes**:
  - `401 Unauthorized`: Invalid `X-Hub-Signature-256` header (signature mismatch). Check secret alignment.
  - `500 Internal Server Error`: `ENVIRONMENT=production` is set, but `GITHUB_WEBHOOK_SECRET` is unset or set to the default dev secret.
- **Remediation**: Configure a cryptographically random webhook secret in both GitHub and the production environment.

### Issue 2: Review Timeout Expirations
- **Symptoms**: Review session fails with a timeout error on external adapters.
- **Mechanism**: The runner executes adapters in a dedicated process session (`start_new_session=True`). On timeout expiration, `os.killpg(SIGKILL)` terminates the process group.
- **Remediation**: Check if repository has unusually large generated files. Add them to `ignored_patterns` in `ReviewConfig` or increase `--timeout`.

### Issue 3: Stale Review Rejection
- **Symptoms**: Review completes successfully, but PR comments are not published.
- **Mechanism**: `GitHubReviewPublisher` checks the live PR head SHA before publishing. If a new commit was pushed during analysis, publication is safely aborted to prevent outdated inline feedback.
- **Remediation**: Expected behavior. The newer commit's webhook will trigger an updated review.
