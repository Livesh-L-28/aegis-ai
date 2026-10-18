# AEGIS AI — Changelog

All notable changes to the AEGIS AI platform are documented in this file.

## [Unreleased] — 1.0.0-rc1

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
