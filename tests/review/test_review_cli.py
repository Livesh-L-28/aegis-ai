"""Tests for aegis review CLI runner and exit codes."""

from pathlib import Path

import pytest

from packages.review.cli import build_parser, run_cli


def test_cli_parser_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args([])
    assert args.repo == "."
    assert args.base is None
    assert args.format == "text"
    assert args.severity_threshold == "ERROR"
    assert args.enable_ai is False
    assert args.enable_tools is False


def test_cli_execution_smoke(capsys: pytest.CaptureFixture[str]) -> None:
    # Running CLI on current repository should succeed cleanly
    exit_code = run_cli(["--repo", ".", "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "repository_path" in captured.out


def test_cli_fails_on_nonexistent_repo(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", "/nonexistent/path/12345"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "does not exist" in captured.err


def test_cli_format_sarif(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", ".", "--format", "sarif"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "sarif-schema-2.1.0.json" in captured.out
    assert "LogicFalcon" in captured.out


def test_cli_format_markdown(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", ".", "--format", "markdown"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "## 🦅 LogicFalcon Code Review Summary" in captured.out


def test_cli_flags_staged_and_show_fixes(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", ".", "--staged", "--show-fixes", "--format", "text"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "LogicFalcon — Repository Intelligence" in captured.out


def test_cli_format_vscode(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", ".", "--format", "vscode"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    # Output is a valid JSON list of VS Code diagnostics
    import json
    parsed = json.loads(captured.out)
    assert isinstance(parsed, list)


def test_cli_config_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json
    cfg_file = tmp_path / ".logicfalcon.json"
    cfg_file.write_text(json.dumps({"per_file_timeout_seconds": 25.0}))
    exit_code = run_cli(["--repo", ".", "--config", str(cfg_file), "--format", "json"])
    assert exit_code in (0, 1)


def test_cli_baseline_suppression(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json
    # Run a review to capture findings
    exit_code = run_cli(["--repo", ".", "--format", "json"])
    assert exit_code in (0, 1)
    captured = capsys.readouterr()
    base_file = tmp_path / "baseline.json"
    base_file.write_text(captured.out)

    # Re-running with baseline should suppress all identical findings
    exit_code_suppressed = run_cli(["--repo", ".", "--baseline", str(base_file), "--format", "json"])
    assert exit_code_suppressed in (0, 1)
    captured_suppressed = capsys.readouterr()
    data = json.loads(captured_suppressed.out)
    assert len(data.get("findings", [])) == 0


