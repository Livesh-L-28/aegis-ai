# AEGIS AI — Repository Intelligence & AI Code Review Engine Architecture

## 1. Executive Summary

The **Repository Intelligence & AI Code Review Engine** is an integrated reliability, quality, and security review capability built natively into the AEGIS AI platform. It complements the existing operational intelligence triad (**System, Code, and Knowledge Intelligence**) with pre-deployment code review and diff reasoning.

The architecture preserves all 7 existing platform phases and strictly adheres to AEGIS layered conventions:
```
FastAPI Router (apps/api/app/api/v1/endpoints/review.py)
       │
       ▼
Application Service (apps/api/app/services/review.py)
       │
       ▼
Domain & AI Review Engine (packages/review/)
       │
       ├─► Git Diff Parser (packages/review/git/diff_parser.py)
       ├─► AST Symbol Mapper (packages/review/analyzer/symbol_mapper.py)
       ├─► Dependency Graph (packages/review/analyzer/dependency_graph.py)
       ├─► Static Analysis Adapters (packages/review/adapters/)
       ├─► Bounded AI Context & Reviewer (packages/review/ai/)
       └─► GitHub Publisher & Webhooks (packages/review/github/)
       │
       ▼
Repositories & Persistence (apps/api/app/repositories/review.py)
       │
       ▼
Database (PostgreSQL / SQLite via SQLAlchemy 2.0 Async)
```

---

## 2. Request-to-Finding Data Flow

The lifecycle of a code review follows an 8-stage deterministic-first pipeline:

```text
[ Git Unified Diff ]
        │
        ▼ (Stage 1: Ingestion & Validation)
[ GitDiffParser ] ──► Extracts hunks, line mappings, validates size (<= 10MB)
        │
        ▼ (Stage 2: Semantic Mapping)
[ SymbolMapper ] ──► Reuses PythonASTParser to correlate diff lines to functions/classes
        │
        ▼ (Stage 3: Impact Analysis)
[ DependencyGraph ] ──► Traces import graph & reverse dependencies to identify affected tests
        │
        ▼ (Stage 4: Deterministic Static Analysis)
[ Static Adapters ] ──► ASTSecurityAdapter (in-process AST) & optional Ruff (subprocess)
        │
        ▼ (Stage 5: Bounded Context Assembly)
[ ContextBuilder ] ──► Bounds diff hunks, symbols, affected tests, and findings (<= 24k chars)
        │
        ▼ (Stage 6: AI Trust Plane Screening)
[ LLM Firewall ] ──► inspect_prompt() screens for prompt injection & data exfiltration
        │
        ▼ (Stage 7: Model Reasoning & Fallback)
[ ModelRouter & AI ] ──► Reuses existing ModelRouter & AIReliabilityPackageAdapter
        │
        ▼ (Stage 8: Output Validation & Persistence)
[ Schema Validation ] ──► Validates Pydantic schema, filters hallucinated files/lines,
                          deduplicates via SHA-256 fingerprint, persists to DB
```

---

## 3. Core Subsystems

### 3.1 Git Diff Parser (`packages/review/git/diff_parser.py`)
* Pure-Python unified Git diff parser operating without invoking shell commands or untrusted scripts.
* Extracts commit hashes (`base_commit`, `head_commit`), file additions, modifications, renames, deletions, and binary files.
* Tracks exact 1-indexed line mappings per hunk (`added_lines`, `deleted_lines`).
* Enforces strict DoS bounds (`max_diff_bytes = 10_000_000`) to prevent memory exhaustion on oversized commits.

### 3.2 AST Symbol Mapper (`packages/review/analyzer/symbol_mapper.py`)
* Reuses existing [`PythonASTParser`](file:///Users/livesh/AEGIS%20AI/packages/intelligence/code/indexer.py) to statically index functions, methods, classes, signatures, and docstrings.
* Correlates diff line modifications directly to semantic code symbols and qualified names (`ClassName.method_name`).

### 3.3 Dependency Graph & Affected Test Discovery (`packages/review/analyzer/dependency_graph.py`)
* Analyzes module imports and reverse dependencies across the repository up to a configurable transitive depth (default: 3).
* Identifies which test suites directly or transitively depend on changed code.
* **Documented Limitations**:
  - Dynamic imports (`importlib`, `__import__`) cannot be statically discovered.
  - Dynamic attribute access (`getattr`, `setattr`) cannot be resolved statically.
  - Global pytest fixtures (e.g., `conftest.py`) affect tests without explicit imports.

### 3.4 Deterministic Static Analysis Adapters (`packages/review/adapters/`)
* **AST Security Adapter (`ast_security.py`)**: In-process AST checks executing in microseconds without subprocess overhead:
  - `SEC-001` (CRITICAL): Arbitrary Code Execution via `eval`/`exec`.
  - `SEC-002` (CRITICAL): Subprocess invocation with `shell=True`.
  - `SEC-003` (CRITICAL): Unredacted credential and secret token patterns.
  - `SEC-004` (ERROR): Insecure deserialization via `pickle.loads` / `pickle.load`.
  - `QUAL-001` (WARNING): Silent exception suppression via broad or bare `except: pass`.
  - `SEC-005` (ERROR): Python syntax errors.
* **Process-Isolated Runner (`runner.py`)**: Executes custom or external adapters (e.g., Ruff) using `subprocess.Popen(..., start_new_session=True)` and scrubs sensitive environment variables. Upon timeout, `os.killpg(SIGKILL)` terminates the process group without hanging caller threads.
* **TypeScript Language Adapter (`typescript_stub.py`)**: Interface-only specification explicitly marked `UNSUPPORTED_IN_MILESTONE_1`. TypeScript AST analysis is intentionally not supported in this release.

### 3.5 Repository-Aware AI Review Engine (`packages/review/ai/`)
* **Context Builder (`context_builder.py`)**: Assembles bounded context packets (changed diff hunks, symbols, imports, affected tests, static findings) with strict token and character caps (default: 24k chars).
* **Defensive Prompting**: Treats source code, diffs, comments, and commit messages as untrusted data to defend against prompt injection.
* **Trust Plane Screening**: Integrates [`LLMFirewallCoreAdapter`](file:///Users/livesh/AEGIS%20AI/packages/security/llm_firewall/adapter.py) (`inspect_prompt` and `inspect_output`) and [`AIReliabilityPackageAdapter`](file:///Users/livesh/AEGIS%20AI/packages/reliability/adapter.py) for graceful fallback handling.
* **Output Validation**: Validates model output against Pydantic schemas, verifies that findings match real changed files and line ranges, and eliminates duplicates via SHA-256 fingerprints.

### 3.6 Persistence & Platform Integration
* **Entities**: `ReviewSessionEntity` and `ReviewFindingEntity` with tenant isolation (`organization_id`).
* **Migrations**: Reversible Alembic migration `0006_code_review_engine.py`.
* **FastAPI Endpoints**: `/api/v1/reviews` with RBAC enforcement (`PROJECT_WRITE` for review triggers, `PROJECT_READ` for querying).

### 3.7 GitHub Pull Request Integration (`packages/review/github/`)
* **Signature Verification**: Constant-time HMAC SHA-256 webhook validation. In production, missing or default secrets fail closed with HTTP 500.
* **Delivery Deduplication**: Tracks `X-GitHub-Delivery` IDs in an LRU cache to guarantee idempotency.
* **Stale-Review Protection**: Verifies that the live PR head SHA matches the analyzed commit before publishing, rejecting outdated results.
* **Inline Positioning**: Maps findings to valid diff hunk lines; automatically places out-of-diff findings in a clean summary table to prevent GitHub API errors.
* **Dry-Run Mode**: Defaults to dry-run preview when external publishing is disabled.

---

## 4. Deployment Profiles & Security Boundaries

| Profile | Execution Mode | Security Controls | Target Use Case |
| :--- | :--- | :--- | :--- |
| **Local CLI** | Read-only terminal command | AST-only by default; read-only file access; no network; no credentials needed. | Individual developer workstations; pre-commit hooks. |
| **Trusted CI** | Subprocess in CI pipeline | Bounded timeouts; scrubbed env; exit code gating on severity thresholds. | Internal repositories in GitHub Actions / GitLab CI. |
| **Multi-Tenant SaaS** | FastAPI Webhook & API | Tenant-scoped DB queries (`organization_id`); constant-time HMAC-SHA256; RBAC gates. | Commercial cloud deployment reviewing customer PRs. |
| **Untrusted Repositories** | **Container Sandbox Required** | Bare-metal subprocess execution is **prohibited**. Custom tools must run inside ephemeral Docker/gVisor microVMs with dropped capabilities and no network. | Public or untrusted third-party code review. |

---

## 5. Architectural Alignment with the 7-Phase Roadmap

The Code Review Engine preserves all 7 existing phases and reuses their mature components:
- **Phase 1 (Enterprise Foundation)**: Reuses logging, error handling, tenant models, and database infrastructure.
- **Phase 2 (Simulation & Observability)**: Emits structured telemetry and review metrics.
- **Phase 3 (Intelligence Triad)**: Reuses `PythonASTParser`, `RepositoryIndexer`, and source code sanitization from Code Intelligence.
- **Phase 4 (Reasoning Engine)**: Reuses `ModelRouter` and provider abstractions for AI diff evaluation.
- **Phase 5 (Trust Plane & Reliability)**: Reuses `LLMFirewallCoreAdapter` and `AIReliabilityPackageAdapter` for prompt screening and fallback handling.
- **Phase 6 (Remediation)**: Complements remediation with pre-deployment code quality gates.
- **Phase 7 (Autonomy & Evaluation)**: Subject to release gates, continuous evaluation, and deterministic circuit breakers.
