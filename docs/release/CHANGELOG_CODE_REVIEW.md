# AEGIS AI — Code Review Engine Release Notes & Changelog

## Version 1.0.0-rc1 — Repository Intelligence & AI Code Review Engine

### Overview
This release introduces the **Repository Intelligence & AI Code Review Engine** as a native, backward-compatible capability within the AEGIS AI platform. It extends the existing operational intelligence triad (System, Code, and Knowledge Intelligence) to pre-deployment diff analysis, combining deterministic AST security checks, reverse dependency analysis, and bounded AI code review under fail-closed security controls.

---

### Key Capabilities Added

#### 1. Unified Diff Parsing (`packages/review/git/diff_parser.py`)
- **Pure-Python Parsing**: Analyzes unified Git diffs without spawning subshells or invoking untrusted system utilities.
- **Hunk-to-Line Indexing**: Tracks exact 1-indexed old and new file line mappings for additions, deletions, renames, and binary files.
- **DoS Safeguards**: Bounded diff size parsing (default 10 MB limit) prevents ReDoS and memory exhaustion on oversized commits.

#### 2. Changed-File & Symbol Analysis (`packages/review/analyzer/symbol_mapper.py`)
- **AST Symbol Extraction**: Integrates existing `PythonASTParser` to statically map classes, methods, functions, and docstrings.
- **Diff Correlation**: Maps added and modified line ranges directly to enclosing qualified symbol names (e.g., `ClassName.method_name`).

#### 3. Dependency Graph & AffectedTest Discovery (`packages/review/analyzer/dependency_graph.py`)
- **Import Dependency Graph**: Statically traces module import relationships and reverse dependencies up to 3 transitive levels.
- **Affected Test Discovery**: Flags test suites that depend directly or transitively on changed code.
- **Explicit Disclosures**: Documents known limitations regarding dynamic imports (`importlib`), reflection (`getattr`), and global pytest fixtures in `conftest.py`.

#### 4. Deterministic Python AST Security Checks (`packages/review/adapters/ast_security.py`)
- **In-Process AST Security & Quality Analyzers**:
  - **Deterministic AST Rules (`origin: STATIC_ANALYSIS`, confidence 1.0)**:
    - `SEC-001` (CRITICAL): Dangerous dynamic code execution via `eval()` and `exec()`.
    - `QUAL-001` (WARNING): Silent runtime error suppression via `except Exception: pass` or bare `except: pass`.
    - `SEC-005` (ERROR): Python syntax errors in modified code.
  - **Structural Heuristic Rules (`origin: SECURITY_HEURISTIC`, confidence 0.95)**:
    - `SEC-002` (CRITICAL): Command injection via `subprocess(..., shell=True)`.
    - `SEC-004` (ERROR): Insecure deserialization via `pickle.loads` / `pickle.load`.
  - **Heuristic Pattern Scans (`origin: SECURITY_HEURISTIC`, confidence 0.85)**:
    - `SEC-003` (CRITICAL): Potential unredacted credential and secret token pattern detection.

#### 5. Extensible Static Analysis Adapters (`packages/review/adapters/`)
- **Ruff Linter Adapter (`ruff_adapter.py`)**: Subprocess execution in read-only JSON mode with scrubbed environment variables and process timeouts (disabled by default).
- **TypeScript Language Adapter Stub (`typescript_stub.py`)**: Interface-only specification explicitly marked `UNSUPPORTED_IN_MILESTONE_1`. TypeScript AST analysis is intentionally not supported in this release.

#### 6. Bounded AI Review Context & Schema-Validated Findings (`packages/review/ai/`)
- **Context Builder (`context_builder.py`)**: Assembles bounded context packets (changed diff hunks, symbols, imports, affected tests, static findings) with strict token and character caps (default 24k characters).
- **Defensive Prompting**: Treats source code, diffs, comments, and commit messages as untrusted data to defend against prompt injection.
- **LLM Firewall Screening**: Reuses `LLMFirewallCoreAdapter` to screen prompts (`inspect_prompt`) and outputs (`inspect_output`) against data exfiltration and harmful payloads.
- **AI Reliability Integration**: Reuses `AIReliabilityPackageAdapter` for structured fallbacks and failure tolerance.
- **Hallucination Filtering**: Validates model output against strict Pydantic schemas, rejecting findings that reference non-existent files or line numbers outside changed hunks.
- **Deduplication**: Stable 16-character SHA-256 digest prefix deduplicates identical findings across analyzers based on normalized file path, line number, category, and rule ID.

#### 7. Persistent Review Sessions & Entities (`apps/api/app/models/entities.py`)
- **Database Schema**: Reversible Alembic migration `0006_code_review_engine.py` adds `review_sessions` and `review_findings` tables.
- **Async Repositories**: `ReviewSessionRepository` and `ReviewFindingRepository` implemented via SQLAlchemy 2.0 Async.

#### 8. Tenant Isolation & RBAC Enforcement (`apps/api/app/api/v1/endpoints/review.py`)
- **Tenant Scoping**: All queries enforce strict tenant scoping via `organization_id`. Cross-tenant review session IDs return HTTP 404.
- **RBAC Roles**: Triggering reviews requires `Role.ADMIN` or `Role.SECURITY_ENGINEER` (`PROJECT_WRITE`). Querying sessions requires `PROJECT_READ`.

#### 9. GitHub Webhook Security & Idempotency (`packages/review/github/`)
- **Constant-Time HMAC-SHA256**: Validates `X-Hub-Signature-256` before parsing payload or tracking events.
- **Fail-Closed Secrets**: In production (`ENVIRONMENT=production`), missing or default secrets raise `WebhookSecurityError` and return HTTP 500.
- **Delivery Idempotency**: Deduplicates deliveries via `X-GitHub-Delivery` caching.
- **Stale-Head Rejection**: Checks live PR head SHA before publishing, automatically aborting publication if newer commits were pushed.
- **Dry-Run Safe**: Defaults to dry-run mode when publication tokens are absent.

#### 10. Read-Only CLI & CI Integration (`packages/review/cli.py`)
- **Terminal Review**: `aegis review --repo <path>` outputs human-readable tables or machine-readable JSON (`--format json`).
- **Severity Threshold Gating**: `--severity-threshold {INFO,WARNING,ERROR,CRITICAL}` sets CI exit code (0 for pass, 1 for blocking findings).

#### 11. Cooperative Cancellation & Bounded Execution (`packages/review/adapters/runner.py`)
- **Enforceable Process Group Timeouts**: External adapter subprocesses run in isolated process sessions (`start_new_session=True`). On timeout, `os.killpg(SIGKILL)` terminates the process group without hanging caller threads.
- **Cooperative Cancellation**: Review sessions respect cooperative cancellation tokens, immediately halting execution and rendering state immutably `CANCELLED`.

---

### Known Limitations & Operational Constraints

1. **TypeScript / Multi-Language Support**:
   - Python AST analysis is fully supported.
   - TypeScript AST parsing is a stub (`UNSUPPORTED_IN_MILESTONE_1`).
2. **Untrusted Code Execution Boundary**:
   - In-process AST checks (`ast_security`) are purely read-only and safe for untrusted code.
   - External subprocess tools (e.g., linters) run with bounded timeouts and scrubbed environments on bare metal.
   - For multi-tenant SaaS environments running arbitrary repository tools on untrusted user code, execution **must** take place inside an isolated container sandbox (e.g., ephemeral Docker/gVisor/Firecracker microVM).
3. **Dynamic Import Discovery**:
   - Reverse dependency tracking relies on static AST import parsing. Dynamic imports (`importlib.import_module`, `__import__`) and dynamic attributes (`getattr`) cannot be resolved statically.
