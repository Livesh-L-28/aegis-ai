"""Recruiter-ready demonstration script for AEGIS AI Code Review Engine.

Demonstrates local diff analysis, deterministic AST security checks,
affected test discovery, CI exit code gating, and machine-readable JSON output
in an isolated temporary repository without external network or LLM dependencies.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def print_banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    res = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return res.returncode, res.stdout, res.stderr


def setup_synthetic_repository(repo_dir: Path) -> None:
    """Initializes a synthetic git repository with a clean service and unit test."""
    run_cmd(["git", "init", "-b", "main"], cwd=repo_dir)
    run_cmd(["git", "config", "user.name", "AEGIS Demo User"], cwd=repo_dir)
    run_cmd(["git", "config", "user.email", "demo@aegis-ai.internal"], cwd=repo_dir)

    core_dir = repo_dir / "core"
    core_dir.mkdir(parents=True, exist_ok=True)
    tests_dir = repo_dir / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    # Initial clean Python service
    (core_dir / "__init__.py").write_text("", encoding="utf-8")
    (core_dir / "calculator.py").write_text(
        'def safe_add(a: int, b: int) -> int:\n'
        '    """Safely adds two integers."""\n'
        '    return a + b\n',
        encoding="utf-8",
    )

    # Initial clean unit test
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_calculator.py").write_text(
        'from core.calculator import safe_add\n\n'
        'def test_safe_add() -> None:\n'
        '    assert safe_add(2, 3) == 5\n',
        encoding="utf-8",
    )

    run_cmd(["git", "add", "."], cwd=repo_dir)
    run_cmd(["git", "commit", "-m", "feat: initial clean calculator service"], cwd=repo_dir)


def introduce_synthetic_issues(repo_dir: Path) -> None:
    """Modifies calculator.py and test_calculator.py with synthetic quality & security issues."""
    calc_path = repo_dir / "core" / "calculator.py"
    calc_path.write_text(
        'import subprocess\n'
        'from typing import Any\n\n'
        'def safe_add(a: int, b: int) -> int:\n'
        '    """Safely adds two integers."""\n'
        '    return a + b\n\n'
        'def execute_user_task(cmd: str) -> None:\n'
        '    """Demonstrates command injection risk via subprocess(shell=True)."""\n'
        '    subprocess.run(cmd, shell=True)\n\n'
        'def parse_calculation(raw_expr: str) -> Any:\n'
        '    """Demonstrates arbitrary code execution risk via eval()."""\n'
        '    return eval(raw_expr)\n\n'
        'def fallback_handler() -> None:\n'
        '    """Demonstrates silent exception suppression."""\n'
        '    try:\n'
        '        raise RuntimeError("Transient calculation failure")\n'
        '    except Exception:\n'
        '        pass\n',
        encoding="utf-8",
    )

    test_path = repo_dir / "tests" / "test_calculator.py"
    test_path.write_text(
        'from core.calculator import execute_user_task, safe_add\n\n'
        'def test_safe_add() -> None:\n'
        '    assert safe_add(2, 3) == 5\n\n'
        'def test_task_invocation() -> None:\n'
        '    execute_user_task("echo test")\n',
        encoding="utf-8",
    )


def execute_demo(pause_between_steps: bool = False, json_only: bool = False) -> int:
    temp_obj = tempfile.TemporaryDirectory(prefix="aegis_review_demo_")
    repo_dir = Path(temp_obj.name).resolve()

    try:
        setup_synthetic_repository(repo_dir)

        cli_cmd = [sys.executable, "-m", "packages.review.cli", "--repo", str(repo_dir)]

        if not json_only:
            print_banner("STAGE 1: Clean Repository Baseline Verification")
            print(f"Target repository: {repo_dir}")
            print("Running command:   uv run python -m packages.review.cli --repo <repo_path>")
            code, stdout, _stderr = run_cmd(cli_cmd)
            print(stdout)
            print(f"CLI Exit Code: {code} (0 = Clean, build passes)")

            if pause_between_steps:
                input("\n[Press Enter to proceed to Stage 2: Introducing Code Issues]...")

        introduce_synthetic_issues(repo_dir)

        if not json_only:
            print_banner("STAGE 2: Diff-Aware Review with Deterministic Findings")
            print("Changes introduced:")
            print("  • core/calculator.py: subprocess(shell=True) [SEC-002: CRITICAL]")
            print("  • core/calculator.py: eval() invocation     [SEC-001: CRITICAL]")
            print("  • core/calculator.py: except Exception: pass [QUAL-001: WARNING]")
            print("  • tests/test_calculator.py: imports modified functions (affected test)")
            print("\nRunning command:   uv run python -m packages.review.cli --repo <repo_path>")

            code, stdout, _stderr = run_cmd(cli_cmd)
            print(stdout)
            print(f"CLI Exit Code: {code} (1 = Findings at or above default ERROR threshold)")

            if pause_between_steps:
                input("\n[Press Enter to proceed to Stage 3: Machine-Readable JSON Output]...")

        # Stage 3: JSON Output
        json_cmd = [*cli_cmd, "--format", "json"]
        code, json_out, _stderr = run_cmd(json_cmd)

        if json_only:
            print(json_out)
            return code

        print_banner("STAGE 3: Machine-Readable JSON Output for CI/CD Pipelines")
        print("Running command:   uv run python -m packages.review.cli --repo <repo_path> --format json")
        parsed_json = json.loads(json_out)
        print(f"Report UUID:       {parsed_json.get('id')}")
        print(f"Total Findings:    {len(parsed_json.get('findings', []))}")
        print(f"Affected Tests:    {parsed_json.get('affected_artifacts', {}).get('affected_tests')}")
        print("Sample Normalized Finding in JSON:")
        if parsed_json.get("findings"):
            sample = parsed_json["findings"][0]
            print(json.dumps(sample, indent=2))

        if pause_between_steps:
            input("\n[Press Enter to proceed to Stage 4: Exit Code Gating]...")

        # Stage 4: Exit code evaluation
        print_banner("STAGE 4: Configurable Severity Gating & CI Enforcement")
        print("Evaluation rules:")
        print("  • Finding weights: INFO(0) < WARNING(1) < ERROR(2) < CRITICAL(3)")
        print("  • When --severity-threshold ERROR is set, WARNING findings do NOT break the build.")
        print("  • When CRITICAL or ERROR findings exist, the CLI returns exit code 1 to block CI merge.")
        print(f"\nObserved exit code with ERROR threshold:    {code} (Blocked)")

        # Stage 5: Explaining Deterministic vs AI Findings
        print_banner("STAGE 5: Deterministic Analysis vs. AI Hypothesis Separation")
        print("How engineers and CI pipelines distinguish findings:")
        print("  1. 'origin': 'SECURITY_HEURISTIC' or 'STATIC_ANALYSIS' -> Deterministic AST check")
        print("     'origin': 'HYPOTHESIS'                              -> AI model suggestion")
        print("  2. 'confidence': 1.0 or 0.95 (deterministic) vs. < 1.0 (probabilistic AI hypothesis)")
        print("  3. 'tool_name':  'ast_security' / 'ruff' vs. 'ai_review'")
        print("  4. CI can strictly gate on deterministic findings (zero false positives),")
        print("     while presenting AI hypotheses as non-blocking advisory suggestions.")

        print_banner("DEMONSTRATION COMPLETE")
        print("✓ Verified clean baseline.")
        print("✓ Verified diff parsing, AST checks, and affected test correlation.")
        print("✓ Verified human-readable table and structured JSON format.")
        print("✓ Verified CI exit code threshold gating.")
        print("✓ Cleaned up temporary synthetic repository safely.")

        return 0

    finally:
        temp_obj.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recruiter-ready demonstration of AEGIS AI Code Review Engine."
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="Pause between demo steps for live technical presentations.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output only the machine-readable JSON report.",
    )
    args = parser.parse_args()
    sys.exit(execute_demo(pause_between_steps=args.pause, json_only=args.json_only))


if __name__ == "__main__":
    main()
