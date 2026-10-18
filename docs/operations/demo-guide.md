# AEGIS AI — Code Review Engine Recruiter & Technical Demo Guide

This guide provides a reproducible, standalone demonstration of the **AEGIS AI Repository Intelligence & Code Review Engine**.

The demonstration operates completely offline in a temporary directory:
- **No external GitHub credentials required.**
- **No paid LLM API keys required.**
- **No destructive git operations executed.**
- **Zero modification to user workspace files or existing test databases.**

---

## 1. Prerequisites

- Python 3.12+ installed.
- `uv` package manager installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
- Git installed.

---

## 2. Quick Demonstration Commands

### Option A: Fully Automated Demonstration
Runs all 5 verification stages end-to-end, printing headers, commands, outputs, and exit codes:

```bash
uv run python scripts/demo_review_engine.py
```

### Option B: Interactive Presentation Mode (Recommended for Live Interviews)
Pauses between stages to allow presenting each concept before advancing:

```bash
uv run python scripts/demo_review_engine.py --pause
```

### Option C: Machine-Readable JSON Output
Outputs pure, formatted JSON report for piping to `jq` or CI audit logs:

```bash
uv run python scripts/demo_review_engine.py --json-only
```

---

## 3. What the Demonstration Proves (Stage-by-Stage)

### Stage 1: Clean Baseline Verification
- **Action**: Initializes a clean synthetic Git repository with `core/calculator.py` and `tests/test_calculator.py`. Runs `aegis review`.
- **Observed Result**: 0 findings, `is_clean: true`.
- **Exit Code**: `0` (Clean build passes).

### Stage 2: Diff-Aware Review with Deterministic Findings
- **Action**: Introduces synthetic security and quality issues:
  1. `subprocess.run(cmd, shell=True)` -> Triggers `SEC-002` (CRITICAL: Command Injection).
  2. `eval(raw_expr)` -> Triggers `SEC-001` (CRITICAL: Arbitrary Code Execution).
  3. `except Exception: pass` -> Triggers `QUAL-001` (WARNING: Silent Exception Suppression).
  4. Modifies `tests/test_calculator.py` to import the changed function.
- **Observed Result**:
  - Exact file and 1-indexed line locations (`core/calculator.py:10`, `core/calculator.py:14`, `core/calculator.py:20`).
  - Correlated semantic symbols extracted via AST.
  - Automatically identifies `tests/test_calculator.py` as an affected test requiring re-execution.
  - Generates actionable remediation suggestions.
- **Exit Code**: `1` (Findings at or above default `ERROR` threshold block merge).

### Stage 3: Machine-Readable JSON Output for CI/CD Pipelines
- **Action**: Executes `aegis review --repo <path> --format json`.
- **Observed Result**: Complete JSON payload conforming to Pydantic domain models:
  - Report ID (UUIDv4) and execution duration (typically < 0.005s).
  - Hunk-by-hunk diff summary with added/deleted line counts.
  - Reverse dependency map and affected test list.
  - Deterministic SHA-256 deduplication fingerprint per finding.

### Stage 4: Configurable Severity Gating & CI Enforcement
- **Action**: Demonstrates severity threshold filtering:
  - Weights: `INFO(0) < WARNING(1) < ERROR(2) < CRITICAL(3)`.
  - When `--severity-threshold ERROR` is set, `WARNING` findings are non-blocking.
  - When `CRITICAL` or `ERROR` findings exist, the CLI returns exit code `1` to fail CI workflows.

### Stage 5: Deterministic Analysis vs. AI Hypothesis Separation
- **Key Architecture Takeaway**:
  - Deterministic findings have `origin: "SECURITY_HEURISTIC"` or `"STATIC_ANALYSIS"`, `confidence: 1.0`, and `tool_name: "ast_security"`.
  - AI-generated findings have `origin: "HYPOTHESIS"`, `confidence < 1.0`, and `tool_name: "ai_review"`.
  - CI pipelines can strictly gate on deterministic findings with zero false positives, while surfacing AI suggestions as non-blocking advisory review comments.

---

## 4. Suggested 3–5 Minute Presentation Flow

| Timestamp | Presentation Phase | Talking Points | Action |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:45** | **The Problem & Vision** | "Most AI code review tools either hallucinate file paths or flood developers with false positives. In AEGIS AI, we built a hybrid engine: deterministic AST security checks provide zero-false-positive blocking gates, while AI models provide deep contextual reasoning within bounded limits." | Open terminal in `/Users/livesh/AEGIS AI`. |
| **0:45 - 1:45** | **Baseline & Clean Review** | "We start with a clean baseline repository. AEGIS uses a pure-Python unified diff parser—no shell injection risks, no ReDoS on large diffs." | Run `uv run python scripts/demo_review_engine.py --pause`. Review Stage 1. |
| **1:45 - 2:45** | **Diff Analysis & Findings** | "Now we introduce real-world vulnerabilities: a `shell=True` command injection, an `eval()` arbitrary code execution, and silent exception suppression. Notice how the AST parser maps diff lines directly to semantic functions and identifies affected unit tests." | Press Enter to advance to Stage 2. Highlight rule IDs, line numbers, and affected test detection. |
| **2:45 - 3:45** | **CI/CD & JSON Schema** | "For CI/CD, the CLI outputs structured JSON with deterministic SHA-256 deduplication hashes. Notice the exit code: because CRITICAL findings are present, it returns 1, cleanly failing the GitHub Actions pipeline." | Advance to Stages 3 and 4. Show the JSON payload and exit code. |
| **3:45 - 4:30** | **Enterprise Hardening & Q&A** | "Under the hood, we remediated 4 critical enterprise findings: path traversal defense (`is_relative_to`), process group `SIGKILL` timeout kills, production webhook secret fail-closed behavior, and cooperative cancellation tokens." | Advance to Stage 5 and conclusion. Invite technical questions. |

---

## 5. Troubleshooting

- **Error: `ModuleNotFoundError: No module named 'packages'`**:
  Ensure you are using `uv run python ...` so that the local virtual environment and package paths are loaded.
- **Error: `git command failed`**:
  Ensure git is installed and configured in your path (`git --version`).
- **Reviewing a specific custom repository**:
  Run `uv run python -m packages.review.cli --repo /path/to/repo --base main`.
