"""Tests for aegis review CLI runner and exit codes."""

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
