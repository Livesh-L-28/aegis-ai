"""Tests for LogicFalcon multi-IDE interfaces, structured outputs, and engine bridge."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from logicfalcon import __product__, __version__
from logicfalcon.sdk import review_file
from packages.review.domain.models import FindingSeverity


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_cli_capabilities_command(repo_root: Path) -> None:
    res = subprocess.run(
        [sys.executable, "-m", "logicfalcon.cli", "capabilities"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["product"] == __product__
    assert data["version"] == __version__
    assert data["ast_analyzer_available"] is True
    assert "review_file" in data["capabilities"]
    assert "review_workspace" in data["capabilities"]
    assert "apply_fix" in data["capabilities"]


def test_cli_doctor_json_format(repo_root: Path) -> None:
    res = subprocess.run(
        [sys.executable, "-m", "logicfalcon.cli", "doctor", "--format", "json"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["product"] == __product__
    assert data["python_meets_requirement"] is True
    assert isinstance(data["capabilities"], list)


def test_cli_review_file_json(repo_root: Path) -> None:
    res = subprocess.run(
        [sys.executable, "-m", "logicfalcon.cli", "review", "--file", "logicfalcon/cli.py", "--format", "json"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["repository_path"] == str(repo_root)
    assert "logicfalcon/cli.py" in data["files_reviewed"]
    assert isinstance(data["findings"], list)


def test_cli_review_file_stdin_buffer_with_findings(repo_root: Path) -> None:
    buffer = "def test_func(cache={}):\n    pass\n"
    res = subprocess.run(
        [sys.executable, "-m", "logicfalcon.cli", "review", "--file", "sample_buffer.py", "--stdin", "--format", "json"],
        cwd=str(repo_root),
        input=buffer,
        capture_output=True,
        text=True,
        check=False,
    )
    # Finding triggers non-zero code if severity >= ERROR, but mutable default is WARNING
    # In either case, stdout must contain structured findings
    data = json.loads(res.stdout)
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert finding["rule_id"] == "QUAL-002"
    assert finding["severity"] == "WARNING"
    assert finding["location"]["file_path"] == "sample_buffer.py"
    assert finding["location"]["start_line"] == 1
    assert finding["proposed_fix"] is not None
    assert finding["proposed_fix"]["replacement_code"] == "None"


def test_cli_review_file_vscode_format(repo_root: Path) -> None:
    buffer = "def test_func(cache={}):\n    pass\n"
    res = subprocess.run(
        [sys.executable, "-m", "logicfalcon.cli", "review", "--file", "sample_buffer.py", "--stdin", "--format", "vscode"],
        cwd=str(repo_root),
        input=buffer,
        capture_output=True,
        text=True,
        check=False,
    )
    diagnostics = json.loads(res.stdout)
    assert len(diagnostics) == 1
    diag = diagnostics[0]
    assert diag["file"] == "sample_buffer.py"
    assert diag["line"] == 1
    assert diag["code"] == "QUAL-002"
    assert diag["severity"] == "Warning"
    assert diag["source"] == "LogicFalcon"


def test_sdk_review_file_and_buffer(repo_root: Path) -> None:
    # 1. Clean file review
    report = review_file(file_path="logicfalcon/sdk.py", repo_root=repo_root)
    assert report.is_clean is True
    assert "logicfalcon/sdk.py" in report.files_reviewed

    # 2. In-memory buffer review
    buffer = "eval('2 + 2')\n"
    report_bad = review_file(file_path="inline_eval.py", repo_root=repo_root, content=buffer)
    assert len(report_bad.findings) >= 1
    eval_finding = next((f for f in report_bad.findings if f.rule_id == "SEC-001"), None)
    assert eval_finding is not None
    assert eval_finding.severity == FindingSeverity.CRITICAL


def test_cli_apply_fix_validation(repo_root: Path) -> None:
    # Attempting to apply fix to nonexistent or outside path
    bad_fix = {
        "file_path": "../outside.py",
        "start_line": 1,
        "end_line": 1,
        "replacement_code": "print('hacked')",
    }
    res = subprocess.run(
        [sys.executable, "-m", "logicfalcon.cli", "apply-fix", "--fix", json.dumps(bad_fix), "--dry-run"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode != 0
    data = json.loads(res.stdout or res.stderr)
    assert data["success"] is False
