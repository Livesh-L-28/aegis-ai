# AEGIS AI — Code Review Engine Technical Walkthrough & Interview Guide

This guide is designed for engineering interviews and architectural deep-dives on the **AEGIS AI Repository Intelligence & Code Review Engine**.

---

## 1. Core Architectural Concepts

### 1. The Problem the Code Review Engine Solves
Traditional code reviews face two extremes:
- **Pure Linters/SAST**: Fast and deterministic, but blind to semantic intent, diff context, and cross-file architectural blast radius.
- **Pure LLM Reviewers**: High context awareness, but prone to hallucinating non-existent files or line numbers, generating false positives, succumbing to prompt injection in source code, and running slowly/expensively.

**AEGIS AI Solution**: A hybrid, layered architecture where deterministic in-process AST analyzers provide immediate, high-precision blocking gates for syntactic and structural defects, while bounded AI reasoning analyzes architectural risks and semantic flaws within strict validation schemas and trust plane firewalls.

---

### 2. Why Deterministic Static Analysis and AI Review are Complementary
- **Division of Responsibility**:
  - In-process rules (`ast_security`) evaluate structural code patterns and syntax errors deterministically (e.g., `eval()`, `exec()`, and syntax errors at confidence 1.0; `subprocess(shell=True)` at confidence 0.95), alongside regex heuristic scans for potential unredacted secrets (confidence 0.85), executing in-process without subprocess overhead.
  - AI models (`ai_review`) evaluate cross-cutting design concerns, API contract subtleties, and edge-case logic that cannot be expressed in static regex or AST visitors.
- **CI Pipeline Gating**:
  - Static analyzer findings (`origin: STATIC_ANALYSIS` with confidence 1.0, or `origin: SECURITY_HEURISTIC` with confidence 0.85–0.95) trigger build failures (`exit 1`) when meeting or exceeding the configured `--severity-threshold` (default: ERROR).
  - AI findings (`origin: HYPOTHESIS`, confidence < 1.0) are surfaced as advisory comments, preventing pipeline disruption from model variability.

---

### 3. The Request-to-Finding Data Flow
An 8-stage pipeline converts raw Git diffs into validated, persisted findings:
1. **Diff Ingestion**: Unified Git diff is ingested and parsed into structured `DiffHunk` and `ChangedFile` models.
2. **Hunk Line Indexing**: Every modified line is mapped to 1-indexed old and new file positions.
3. **AST Symbol Mapping**: Modified lines are correlated to enclosing functions and classes via `PythonASTParser`.
4. **Dependency Traversal**: `DependencyGraph` traces module imports and reverse dependencies to identify affected test suites.
5. **Deterministic Static Adapters**: In-process AST checks run on changed files.
6. **Bounded Context Assembly**: `ContextBuilder` aggregates diff hunks, symbol definitions, and affected tests within token bounds (default 24k chars).
7. **Trust Plane Screening & Reasoning**: `LLMFirewallCoreAdapter` inspects prompts for injection and exfiltration; `ModelRouter` executes the LLM with fallback handling from `AIReliabilityPackageAdapter`.
8. **Schema Validation & Deduplication**: Pydantic schema validation rejects malformed responses; hallucinated line numbers are discarded; an abbreviated 16-character SHA-256 digest prefix based on file path, line number, category, and rule ID deduplicates findings before persistence.

---

### 4. Diff Parsing, Path Containment, AST Checks, and Dependency Analysis
- **Diff Parsing (`diff_parser.py`)**: Pure-Python state machine parsing unified diff headers (`diff --git`, `---`, `+++`, `@@ -l,s +l,s @@`).
- **Path Containment Defense (`validate_contained_path`)**: Resolves candidate file paths against the repository root and checks `resolved_target.is_relative_to(resolved_root)`. Explicitly rejects leading `/` or `\` separators and symlink escapes to prevent reading host files outside the repository.
- **AST Checks (`ast_security.py`)**: Subclasses `ast.NodeVisitor` to inspect syntax trees entirely in-process without spawning subshells.
- **Dependency Analysis (`dependency_graph.py`)**: Extracts module imports from AST nodes, builds forward and reverse dependency maps, and traverses up to 3 transitive levels to discover affected test files.

---

### 5. AI Context Bounds, Schema Validation, and Prompt-Injection Defenses
- **Context Bounds**: Caps diff context at 24k characters to prevent context-window overflow and excessive token spend.
- **Defensive Prompting**: Code snippets and diffs are wrapped in delimiters with explicit system instructions treating code as untrusted input data, instructing the model to ignore any embedded directives or prompt injection attempts.
- **Hallucination Filtering**: Each AI finding's `file_path` and `start_line` are validated against the set of real changed files and line numbers present in the diff hunks. If an AI finding references an unedited file or an invalid line, it is rejected with status `REJECTED_LOCATION`.

---

### 6. LLM Firewall and Reliability Integration
- **LLM Firewall (`LLMFirewallCoreAdapter`)**:
  - `inspect_prompt`: Screens prompt payloads before transmission to detect prompt injection, secret exfiltration, or malicious instructions.
  - `inspect_output`: Screens generated text before deserialization to verify safe output structure.
- **AI Reliability (`AIReliabilityPackageAdapter`)**:
  - Wraps model invocations with retry policies, timeout handling, and fallback providers so that an AI outage does not break review generation.

---

### 7. Tenant Isolation, RBAC, and Review Persistence
- **Tenant Isolation**: Every database table (`review_sessions`, `review_findings`) is scoped by `organization_id`. API queries strictly filter by the authenticated caller's tenant; accessing a foreign review ID yields HTTP 404.
- **RBAC Enforcement**:
  - `PROJECT_WRITE` (`Role.ADMIN`, `Role.SECURITY_ENGINEER`): Required to trigger reviews or cancel review sessions.
  - `PROJECT_READ` (`Role.VIEWER` and above): Required to query review sessions and findings.
- **Persistence**: Implemented via SQLAlchemy 2.0 Async with PostgreSQL/SQLite support and reversible Alembic migration `0006_code_review_engine.py`.

---

### 8. Webhook HMAC Verification, Idempotency, and Stale-Head Rejection
- **Constant-Time HMAC-SHA256**: Validates `X-Hub-Signature-256` using `hmac.compare_digest`.
- **Fail-Closed Secret Enforcement**: In production (`ENVIRONMENT=production`), missing or default secrets raise `WebhookSecurityError` and return HTTP 500, preventing insecure deployments.
- **Idempotency**: Caches `X-GitHub-Delivery` UUIDs to reject replayed webhook deliveries.
- **Stale-Head Protection**: Before publishing review comments, the engine queries the current pull request head commit SHA. If a newer commit was pushed while the review was in flight, publication is aborted.

---

### 9. Timeout Enforcement, Cancellation, and Sandbox Boundaries
- **Enforceable Subprocess Timeouts (`runner.py`)**:
  - External adapters run in a dedicated process session (`subprocess.Popen(..., start_new_session=True)`).
  - On timeout expiration, `os.killpg(SIGKILL)` terminates the entire process group, eliminating orphan processes and bounded caller latency.
- **Cooperative Cancellation**:
  - In-flight reviews check cooperative cancellation tokens between analysis stages.
  - When cancelled, the review halts immediately, discards uncommitted findings, and marks the session immutably `CANCELLED`.
- **Sandbox Limitation (Bare Metal vs. Container)**:
  - Bare-metal subprocess execution cannot guarantee defense against zero-day kernel exploits or raw filesystem tampering from arbitrary third-party code.
  - In multi-tenant SaaS environments, running custom repository linters on untrusted code requires an ephemeral container sandbox (Docker/gVisor/Firecracker microVM).

---

### 10. Testing Strategy
- **Suite Size**: 147 tests (103 baseline platform tests + 32 code review engine tests + 12 security regression tests).
- **Coverage**:
  - Diff parsing and line calculation edge cases (binary files, renames, additions, deletions).
  - Path traversal vectors (`../`, `/etc/passwd`, symlinks, Windows separators).
  - Enforceable timeouts and process group cleanup on hanging adapters.
  - Webhook secret fail-closed logic and HMAC validation.
  - Cooperative cancellation races and state immutability.
  - Tenant isolation and cross-tenant data access denial.

---

## 2. Realistic Technical Interview Questions & Answers

### Q1: How does AEGIS AI prevent arbitrary file read attacks (path traversal) in review diffs?
**Answer**:
"In unified diffs, file headers contain relative paths like `--- a/service.py` and `+++ b/service.py`. A malicious PR could craft diffs with paths like `../../../../etc/shadow` or `/proc/self/environ`. In AEGIS AI, we developed `validate_contained_path`:
1. It rejects any path containing leading slashes (`/` or `\\`).
2. It resolves the absolute path of both the repository root and the target candidate using `Path.resolve()`.
3. It validates that `resolved_target.is_relative_to(resolved_root)`.
4. If a path escapes the root via traversal or symlinks, it returns `None`, and the file is omitted from analysis with zero file content leaked to analyzers, logs, or LLM prompts."

---

### Q2: Why did you use `os.killpg(SIGKILL)` instead of `ThreadPoolExecutor` or `process.kill()` for timeouts?
**Answer**:
"In Python, `ThreadPoolExecutor` has a subtle pitfall: when used as a context manager (`with ThreadPoolExecutor`), its `__exit__` method calls `shutdown(wait=True)`. If a thread is blocked in C-level I/O or an infinite loop, the caller blocks indefinitely despite the timeout.
Similarly, `process.kill()` only terminates the parent process; if the linter spawned child worker processes, they become orphaned zombies consuming CPU and memory.
In AEGIS AI, we launch adapter subprocesses with `start_new_session=True`, creating a new POSIX process group. When `subprocess.communicate(timeout=...)` expires, we call `os.killpg(process.pid, signal.SIGKILL)`, which atomically terminates the parent and all descendant processes, guaranteeing bounded latency (< timeout + 0.1s) and zero resource leaks."

---

### Q3: How do you prevent LLMs from hallucinating file paths and line numbers?
**Answer**:
"We enforce a strict post-generation validation gate:
1. When parsing the Git diff, we build a set of all valid changed file paths and a lookup map of exact 1-indexed line numbers modified in each hunk.
2. The AI reviewer's raw output is first parsed against a strict Pydantic model (`ReviewFinding`).
3. We then check every finding's `file_path` against the changed file set and its `start_line` against the hunk lines.
4. If a finding points to a file that wasn't modified or a line outside the diff hunk, it is marked `REJECTED_LOCATION` and discarded.
This guarantees that 100% of reported review findings reference real, modified code."

---

### Q4: How is tenant isolation enforced in the review engine?
**Answer**:
"Tenant isolation is enforced at every layer:
1. In the database, both `review_sessions` and `review_findings` contain `organization_id` foreign keys indexed for isolation.
2. In the repository layer, queries filter by `organization_id == caller_org_id`.
3. In the API layer, endpoints extract `organization_id` from the verified JWT claims. If a user requests a review session belonging to another organization, the query returns `None`, which translates to HTTP 404 rather than HTTP 403, preventing resource enumeration."

---

### Q5: What are the remaining limitations of the system?
**Answer**:
"There are three explicit operational limitations:
1. **TypeScript Support**: TypeScript AST analysis is currently an unsupported stub; only Python AST parsing is implemented.
2. **Dynamic Imports**: Reverse dependency tracking is static; dynamic imports via `importlib` or pytest `conftest.py` global fixtures cannot be discovered without runtime execution.
3. **OS-Level Sandboxing**: While we enforce process-group timeouts and environment scrubbing on bare metal, executing arbitrary repository-controlled tools on untrusted user code requires container isolation (Docker/gVisor/Firecracker) to guard against zero-day kernel exploits."
