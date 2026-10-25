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


def test_cli_execution_smoke(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Running CLI on isolated fixture repository should succeed cleanly
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "repository_path" in captured.out


def test_cli_fails_on_nonexistent_repo(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", "/nonexistent/path/12345"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "does not exist" in captured.err


def test_cli_format_sarif(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--format", "sarif"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "sarif-schema-2.1.0.json" in captured.out
    assert "LogicFalcon" in captured.out


def test_cli_format_markdown(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--format", "markdown"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "## 🦅 LogicFalcon Code Review Summary" in captured.out


def test_cli_flags_staged_and_show_fixes(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--staged", "--show-fixes", "--format", "text"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    assert "LogicFalcon — Repository Intelligence" in captured.out


def test_cli_format_vscode(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--format", "vscode"])
    captured = capsys.readouterr()
    assert exit_code in (0, 1)
    # Output is a valid JSON list of VS Code diagnostics
    import json
    parsed = json.loads(captured.out)
    assert isinstance(parsed, list)


def test_cli_config_file(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json
    cfg_file = cli_fixture_repo / ".logicfalcon.json"
    cfg_file.write_text(json.dumps({"per_file_timeout_seconds": 25.0}))
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--config", str(cfg_file), "--format", "json"])
    assert exit_code in (0, 1)


def test_cli_baseline_suppression(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json
    # Run a review to capture findings
    exit_code = run_cli(["--repo", str(cli_fixture_repo), "--format", "json"])
    assert exit_code in (0, 1)
    captured = capsys.readouterr()
    base_file = cli_fixture_repo / "baseline.json"
    base_file.write_text(captured.out)

    # Re-running with baseline should suppress all identical findings
    exit_code_suppressed = run_cli(["--repo", str(cli_fixture_repo), "--baseline", str(base_file), "--format", "json"])
    assert exit_code_suppressed in (0, 1)
    captured_suppressed = capsys.readouterr()
    data = json.loads(captured_suppressed.out)
    assert len(data.get("findings", [])) == 0


def test_cli_architecture_subcommand(cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies that logicfalcon architecture CLI runs and outputs structured report."""
    from logicfalcon.cli import run_main

    exit_code = run_main(["architecture", "--repo", str(cli_fixture_repo), "--format", "json"])
    assert exit_code in (0, 1)
    captured = capsys.readouterr()
    import json
    data = json.loads(captured.out)
    assert "health_score" in data
    assert "cycles" in data
    assert "boundary_violations" in data
    assert "module_metrics" in data



