"""Tests for top-level aegis package API and unified CLI commands."""

import pytest

import aegis
from aegis import (
    AutonomousDebuggingService,
    FindingSeverity,
    LocalReviewEngine,
    ReviewConfig,
    ReviewReport,
    __version__,
    build_parser,
    run_cli,
)
from aegis.cli import build_root_parser, run_doctor, run_main


def test_aegis_public_api_exports() -> None:
    assert __version__ == "0.1.0"
    assert aegis.__version__ == "0.1.0"
    assert LocalReviewEngine is not None
    assert ReviewConfig is not None
    assert ReviewReport is not None
    assert FindingSeverity is not None
    assert AutonomousDebuggingService is not None
    assert callable(run_cli)
    assert callable(build_parser)


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["--version"])
    assert code == 0
    captured = capsys.readouterr()
    assert "aegis" in captured.out.lower()
    assert "0.1.0" in captured.out


def test_cli_help_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["--help"])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage: aegis" in captured.out
    assert "review" in captured.out
    assert "doctor" in captured.out


def test_cli_empty_args_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage: aegis" in captured.out


def test_cli_doctor(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_doctor()
    assert code == 0
    captured = capsys.readouterr()
    assert "AEGIS AI — System Diagnostic & Capability Doctor" in captured.out
    assert "[PASS] Python Version" in captured.out
    assert "Python AST Static Analyzer" in captured.out
    assert "TypeScript/JavaScript Static Parser" in captured.out


def test_cli_doctor_via_main(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["doctor"])
    assert code == 0
    captured = capsys.readouterr()
    assert "System diagnostics complete" in captured.out


def test_cli_review_subcommand_dispatch(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["review", "--repo", ".", "--format", "json"])
    assert code in (0, 1)
    captured = capsys.readouterr()
    assert "repository_path" in captured.out


def test_cli_review_direct_flag_dispatch(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["--repo", ".", "--format", "json"])
    assert code in (0, 1)
    captured = capsys.readouterr()
    assert "repository_path" in captured.out


def test_root_parser_build() -> None:
    parser = build_root_parser()
    assert parser.prog == "aegis"
