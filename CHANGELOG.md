# LogicFalcon / AEGIS AI — Changelog

All notable changes to the LogicFalcon developer platform (powered by AEGIS AI) are documented in this file.

## [0.1.2] — 2026-10-19: Multi-IDE Platform & Seven-Pillar Engineering Intelligence

Full multi-IDE integration layer supporting Visual Studio Code, Cursor, and Google Antigravity, combined with the comprehensive Seven-Pillar Engineering Upgrade.

### Highlights & Capabilities
- **Pillar 1 — Deeper Code Intelligence**:
  - Direct and transitive circular dependency detection with canonical normalized cycle representation and DFS depth bounding (`packages/review/analyzer/dependency_graph.py`).
  - Robert C. Martin coupling metrics (Afferent coupling $C_a$, Efferent coupling $C_e$, Instability $I = \frac{C_e}{C_a + C_e}$) for hotspot identification.
  - Architectural boundary rules enforcing forbidden cross-layer imports (e.g. `domain` importing `adapters`).
- **Pillar 2 — Security & Reliability Intelligence**:
  - New deterministic AST security rules: `SEC-008` (Insecure PyYAML `yaml.load` without `SafeLoader`), `SEC-009` (Zip Slip / Tarbomb archive extraction via `extractall` without path containment), and `SEC-010` (XML entity expansion / XXE).
  - New reliability rule: `REL-002` (Missing network request timeouts on `requests`, `httpx`, and `urllib.request`).
  - Deterministic secret redaction: Automatic redaction of credentials in finding evidence with grounding validator support.
  - Offline dependency vulnerability scanner: `DEP-001` matching pinned requirements against a curated local CVE database without external network calls.
- **Pillar 3 — Safe & Trusted Remediation**:
  - Overlapping fix detection to detect and reject conflicting range modifications within the same file.
  - Bottom-to-top batch edit application preserving line coordinates across multi-finding refactorings.
  - Atomic batch execution with `.orig` backup snapshotting and immediate rollback if syntax validation fails.
- **Pillar 4 — CI/CD & Team Workflows**:
  - SARIF v2.1.0 output formatting (`--format sarif`) for native GitHub Code Scanning integration.
  - Baseline suppression (`--baseline <file>`) enabling clean PR checks without blocking on legacy debt.
  - Severity exit code thresholding (`1` for blocking violations, `0` for clean, `2` for configuration/usage error).
- **Pillar 5 — Repository Health & Architecture Insights**:
  - New CLI subcommand: `logicfalcon architecture --repo . [--format text|json] [--max-cycles N]`.
  - Python SDK entry point: `from logicfalcon import analyze_architecture, ArchitectureAnalyzer, ArchitectureReport`.
  - Explainable repository architecture health score (100 base score with documented deductions for cycles, boundaries, and coupling hotspots).
- **Pillar 6 — AI Agents, MCP, & Automation**:
  - Stdio Model Context Protocol (MCP) server (`logicfalcon mcp`) with new `logicfalcon_analyze_architecture` tool.
  - Credential redaction on all outgoing MCP payloads to prevent agent context leakage.
  - Strict path traversal containment and mandatory explicit `approved=True` mutation boundaries for automated fixes.
- **Pillar 7 — Package Quality, Extensibility, & DX**:
  - Formal custom adapter registration via `AnalyzerRegistry` and `global_analyzer_registry`.
  - Production VSIX multi-IDE platform extension (`extensions/vscode`) with real-time diagnostics and QuickFix actions.
  - Cursor (`.cursorrules`) and Google Antigravity IDE workspace skill (`.agents/skills/logicfalcon/SKILL.md`) integration.
  - Zero-bloat distribution packaging excluding server-side enterprise services from wheel and sdist.
- **Reverse Engineering Intelligence & Review Engine Integration (Phase 9)**:
  - **Review Engine Integration**: Two-way integration between `LocalReviewEngine` and `ReverseEngineeringEngine`. Finding metadata enriched with architectural component (`re_component`), architectural layer (`re_layer`), blast radius / reverse dependency count (`reverse_dependencies_count`), affected entry points (`entry_points_affected`), associated routes (`associated_routes`), and associated data models (`associated_models`).
  - **Security Invariant Guarantee**: Strict guarantee that reverse engineering context never suppresses, downgrades, or modifies security findings or verdicts.
  - **Scanning Hardening**: Traversal bounded by `max_depth` (default: 15), `max_files` (default: 10,000), file size limit (`max_file_size_bytes`, checked before reading), and overall time budget (`timeout_seconds`). Real-directory tracking defends against circular symlink loops; out-of-boundary directory symlinks recorded as structured limitations.
  - **Comprehensive Secret Redaction**: Multi-pattern redaction (`redact_secrets_in_text`) sanitizing token patterns (`ghp_`, `AKIA`), database connection strings (`postgres://user:[REDACTED_PASSWORD]@...`), credentials, and environment variable defaults across Markdown, JSON, plain text, and Mermaid diagrams.
  - **Static Analysis Accuracy**: Nested function and class qualification with scope stacks (`outer.<locals>.inner`), explicit decorator tracking, parameter extraction, and symbol deduplication. Disambiguated SQLAlchemy vs. Pydantic model classification with inheritance propagation. Explicit auth detection (`Depends`, `Security`, `@login_required`) distinguishing verified authentication from unauthenticated routes.
  - **Safe Report Generation**: Mermaid label and identifier sanitization, atomic report writing via `.tmp` file replacement, and strict refusal to overwrite source code files (`.py`, `.ts`, etc.).
  - **CLI & SDK Enhancement**: Added `--with-re-context` to `logicfalcon review`, `--with-review` and `--max-depth` to `logicfalcon reverse-engineer`. Programmatic SDK exports `reverse_engineer` and `reverse_engineer_with_review` with format conversion (`format_type='markdown'|'json'|'text'`).
- **Cross-Repository Intelligence, Change Impact Analysis & Predictive Test Selection (Phase 10)**:
  - **Deterministic Change-Set Acquisition**: Safe git inspection supporting unstaged working tree diffs, staged index diffs, revision range comparisons (`base...target` with merge-base fallback), and explicit file list mode. Full support for additions, modifications, deletions, and file renames (`old_path -> new_path`). Safe argument-list subprocess invocation preventing shell injection.
  - **Dependency-Aware Impact Propagation**: Reverse dependency propagation traversing call graphs, AST module imports, and architectural tiers. Bounded BFS traversal defending against cyclic graphs, enforcing depth limits (`max_depth`, default: 5) and entity limits (`max_entities`, default: 500) while computing canonical shortest explanatory paths.
  - **Explainable Multi-Factor Scoring**: Transparent risk assessment scoring changes from `0.0` to `100.0` and categorizing risk as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Scoring accounts for dependency depth, entry-point reachability, core data model modifications, cross-tier layer boundaries, active security findings, and test coverage adequacy.
  - **Predictive Test Selection**: Static-analysis driven test selection categorizing test associations into directly modified tests, direct consumers, transitive dependents, and naming convention candidates. Includes conservative fallback mode (`--conservative-tests`) selecting all repository tests when analysis coverage is incomplete.
  - **Cross-Layer & Entry-Point Tracing**: Integrated tracing from modified models and modules up through services and handlers to external API routes and CLI entry points.
  - **LocalReviewEngine Integration**: Unified workflow enriching review report metadata with change impact context without suppressing or modifying security finding severity or security verdicts.
  - **CLI & SDK Interfaces**: New CLI subcommand `logicfalcon impact` supporting `--repo`, `--base`, `--target`, `--staged`, `--unstaged`, `--files`, `--format (json|markdown|text)`, `--output-file`, `--conservative-tests`, `--with-review`, and `--fail-on-risk`. Programmatic SDK exports `analyze_impact` and `analyze_impact_with_review`.
  - **Adversarial Safety & Reporting**: Global secret redaction across reports and Mermaid diagrams, path containment validation preventing directory traversal escapes, strict source file overwrite refusal, and atomic writing via `.tmp` file replacement.
- **Continuous Engineering Intelligence, Historical Repository Health & Regression Analytics (Phase 11)**:
  - **Versioned Repository Snapshot Model**: Immutable, schema-versioned (`1.0.0`) snapshots tracking repository metadata, privacy-conscious SHA256 repo identifier, clean commit / staged / working-tree status, analyzer configuration fingerprint, scan coverage counters (discovered, parsed, skipped), limitations, and normalized findings.
  - **SQLite-Backed Safe Local Persistence**: Atomic transactional persistence with `schema_migrations`, dedicated indexes for fast revision and timestamp queries, multi-pattern credential redaction on write, and explicit user-confirmed pruning (`prune_snapshots(keep_last_n, older_than_days)`).
  - **Finding Lifecycle & False-Resolution Defense**: Stable fingerprint-driven lifecycle classification (`NEW`, `UNCHANGED`, `RESOLVED`, `REOPENED`, `CHANGED`, `UNCERTAIN`). Critical safeguard: findings in unparsed, skipped, or disabled-rule files are marked `UNCERTAIN` rather than falsely reported as `RESOLVED`.
  - **Deterministic Pairwise Snapshot Comparison**: Comparability validation checking schema version, analyzer configuration fingerprints, and scan coverage drops. Computes metric deltas (`health_score_delta`, `tech_debt_delta`, etc.) and identifies regressions (new critical/high findings, reopened defects, cycle increases, layer boundary violations).
  - **Engineering Trend Analytics**: Chronological trend analysis calculating health and debt directional trajectories (`IMPROVING`, `DETERIORATING`, `STABLE`, `INSUFFICIENT_DATA`), debt velocities, and recurring defect hotspot frequencies.
  - **Transparent Technical Debt Estimation**: Defensible weighted debt point scoring (Critical: 20 pts, High: 8 pts, Medium: 3 pts, Low: 1 pt; cycles: 5 pts, boundary violations: 4 pts, coupling hotspots: 2.5 pts) with breakdown across severities, categories, and file hotspots.
  - **Configurable Engineering Policy Gates**: Evaluator supporting `BLOCKING`, `WARNING`, and `INFORMATIONAL` modes for CI quality gates (e.g., `max_new_critical_findings`, `max_new_high_findings`, `max_new_cycles`, `max_new_boundary_violations`, `max_health_score_drop`, `max_tech_debt_growth`) with JSON configuration loading.
  - **Comprehensive Multi-Format Reporting**: Deterministic Markdown, JSON, and Text generation for snapshots, comparisons, trends, debt, and policy gates. Enforces global secret redaction, path containment checks, atomic `.tmp` writing, and strict refusal to overwrite source code files.
  - **CLI & SDK Interfaces**: Added CLI subcommand `logicfalcon history` with actions `snapshot`, `list`, `compare`, `trends`, `debt`, `policy`, and `prune`. SDK functions `capture_snapshot`, `list_snapshots`, `compare_snapshots`, `analyze_trends`, `estimate_debt`, and `evaluate_history_policy`.
  - **Quality & Verification**: 25 dedicated unit, integration, adversarial, and benchmark tests added. Verified across clean wheel build, twine validation, and isolated clean virtual environment execution.



## [0.1.0] — 2026-10-18: LogicFalcon Initial Open-Source Release

Initial public open-source release of **LogicFalcon** under the Apache License 2.0.

### Highlights & Capabilities
- **Deterministic Static Code Review**: AST-grounded repository intelligence engine for local Git diff analysis.
- **Multi-Language AST Parsers**: Static symbol and dependency extraction for Python (`PythonASTParser`) and JavaScript/TypeScript (`JavaScriptTypeScriptParser`).
- **In-Process Security Rules**: Deterministic checks for hardcoded credentials (`SEC-003`), unsafe subprocess calls with `shell=True` (`SEC-002`), arbitrary dynamic execution via `eval`/`exec` (`SEC-001`), insecure pickle deserialization (`SEC-004`), and broad exception suppression (`QUAL-001`).
- **Reverse Dependency Traversal**: Automated discovery of test files impacted by source modifications.
- **Unified Developer CLI**: Added `logicfalcon` CLI exposing `review` and `doctor` subcommands.
- **Backwards Compatibility**: Preserved `aegis` CLI entry point as a drop-in compatibility alias.
- **Python SDK**: Exported core domain models (`LocalReviewEngine`, `ReviewConfig`, `ReviewReport`, `FindingSeverity`, `AutonomousDebuggingService`) via `logicfalcon`.
- **Open-Source Licensing**: Released under Apache License 2.0 with inbound=outbound contributor guidelines and separate trademark reservation.

---

## [Unreleased] — 1.0.0-rc1 (AEGIS AI Core)

### Repository Intelligence & AI Code Review Engine
- **Unified Diff Parsing**: Added pure-Python unified Git diff parser (`packages/review/git/diff_parser.py`) tracking 1-indexed hunk line numbers, additions, deletions, renames, and binary files with bounded memory limits.
- **AST Symbol Mapping**: Added AST symbol extraction and line-range correlation (`packages/review/analyzer/symbol_mapper.py`) reusing `PythonASTParser`.
- **Dependency Graph & Affected Tests**: Added static import dependency graph and reverse dependency traversal (`packages/review/analyzer/dependency_graph.py`) to discover test suites affected by diff changes.
- **Deterministic AST Security Analyzers**: Added in-process AST security rules (`packages/review/adapters/ast_security.py`) for `eval`/`exec` (`SEC-001`), `subprocess(shell=True)` (`SEC-002`), hardcoded credentials (`SEC-003`), insecure pickle deserialization (`SEC-004`), broad exception suppression (`QUAL-001`), and syntax errors (`SEC-005`).
- **Static Analysis Runner**: Added subprocess runner (`packages/review/adapters/runner.py`) with process group isolation (`start_new_session=True`), environment scrubbing, and `SIGKILL` timeout enforcement.
- **Bounded AI Review Engine**: Added repository-aware AI reviewer (`packages/review/ai/reviewer.py`) with strict prompt bounds, defensive prompting against prompt injection, LLM Firewall screening, AI Reliability fallback handling, and Pydantic schema validation.
- **Hallucination Protection**: Validated all AI finding locations against real changed files and line ranges, rejecting fabricated findings.
- **Database Persistence**: Added `ReviewSessionEntity` and `ReviewFindingEntity` with Alembic migration `0006_code_review_engine.py` and SQLAlchemy 2.0 Async repositories.
- **Tenant-Scoped API**: Added REST endpoints under `/api/v1/reviews` with tenant isolation (`organization_id`) and RBAC permissions (`PROJECT_WRITE` / `PROJECT_READ`).
- **GitHub Webhook & PR Publisher**: Added HMAC-SHA256 webhook verifier (`packages/review/github/webhook.py`) with fail-closed production secret enforcement, delivery deduplication, stale-head commit protection, and dry-run safety.
- **Read-Only CLI**: Added `aegis review` CLI (`packages/review/cli.py`) with text and JSON formats and configurable severity threshold CI exit codes.
- **Recruiter Demonstration**: Added standalone demonstration script (`scripts/demo_review_engine.py`) for reproducible, zero-credential local evaluations.

For detailed release notes, see [`docs/release/CHANGELOG_CODE_REVIEW.md`](docs/release/CHANGELOG_CODE_REVIEW.md).
