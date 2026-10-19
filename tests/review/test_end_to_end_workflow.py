"""Deterministic end-to-end review workflow test.

Verifies:
1. Deterministic git repository creation with known bug (QUAL-002 mutable default).
2. Complete review execution and finding detection with technical evidence and context.
3. Report generation via CLI with multi-format and show-fixes support.
4. Approval gate enforcement (attempting fix without approved=True raises FixApprovalRequiredError).
5. Isolated remediation verification (isolated workspace copy, syntax check, and simulation).
6. Safe patch application with explicit approval.
7. Post-fix re-review confirming resolution and truthful final status.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import logicfalcon
from packages.review.cli import run_cli
from packages.review.domain.models import FindingCategory, FindingSeverity, ProposedFix
from packages.review.fix_engine import FixApprovalRequiredError


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "ci@logicfalcon.ai"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "LogicFalcon CI"], cwd=path, check=True, capture_output=True)

    # Initial clean commit
    initial_file = path / "README.md"
    initial_file.write_text("# Test Repo\n")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=path, check=True, capture_output=True)


def test_deterministic_e2e_review_and_safe_remediation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _init_git_repo(tmp_path)

    # Introduce a file with a known quality issue (QUAL-002: mutable default argument)
    buggy_code = (
        "def process_data(items=[]):\n"
        "    \"\"\"Process items.\"\"\"\n"
        "    return items\n"
    )
    code_path = tmp_path / "service.py"
    code_path.write_text(buggy_code)

    # Stage the file so git diff includes it
    subprocess.run(["git", "add", "service.py"], cwd=tmp_path, check=True, capture_output=True)

    # 1. Execute full review via LogicFalcon SDK
    report = logicfalcon.review(repo=tmp_path, staged=True)
    assert len(report.files_reviewed) >= 1
    assert len(report.findings) >= 1

    qual2_finding = next((f for f in report.findings if f.rule_id == "QUAL-002"), None)
    assert qual2_finding is not None
    assert qual2_finding.category == FindingCategory.QUALITY
    assert qual2_finding.severity == FindingSeverity.WARNING
    assert "process_data" in (qual2_finding.location.symbol_name or "")
    assert qual2_finding.why_it_matters != ""
    assert qual2_finding.proposed_fix is not None

    # 2. CLI output verification (JSON report)
    exit_code = run_cli(["--repo", str(tmp_path), "--staged", "--format", "json", "--show-fixes"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)

    parsed_output = json.loads(captured.out)
    assert "findings" in parsed_output
    assert any(f["rule_id"] == "QUAL-002" for f in parsed_output["findings"])

    # 3. Approval gate enforcement: Fix application MUST be rejected without approved=True
    suggested_fix = ProposedFix(
        file_path="service.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None):",
        explanation="Safely use None as default argument",
    )

    with pytest.raises(FixApprovalRequiredError):
        logicfalcon.apply_fix(
            fix=suggested_fix,
            repo_root=tmp_path,
            approved=False,
        )

    # 4. Isolated verification before touching working tree
    remediation_result = logicfalcon.verify_fix(
        fixes=[suggested_fix],
        repo_root=tmp_path,
        run_tests=False,
        run_linters=False,
    )
    assert remediation_result.syntax_valid is True
    assert remediation_result.success is True
    assert remediation_result.fixes_applied == 1

    # Confirm original file was NOT modified by verify_fix
    assert "items=[]" in code_path.read_text()

    # 5. Apply fix with explicit human approval
    apply_result = logicfalcon.apply_fix(
        fix=suggested_fix,
        repo_root=tmp_path,
        approved=True,
        create_backup=True,
    )
    assert apply_result.success is True
    assert "def process_data(items=None):" in code_path.read_text()
    assert "items=[]" not in code_path.read_text()
    assert apply_result.backup_path is not None
    assert Path(apply_result.backup_path).exists()

    # 6. Stage fixed file and re-run review: QUAL-002 should no longer be present
    subprocess.run(["git", "add", "service.py"], cwd=tmp_path, check=True, capture_output=True)
    re_report = logicfalcon.review(repo=tmp_path, staged=True)
    re_finding_rules = {f.rule_id for f in re_report.findings}
    assert "QUAL-002" not in re_finding_rules
    assert len(re_report.findings) == 0
