"""Tests for LogicFalcon product branding, public API, and CLI commands."""

from pathlib import Path

import pytest

import logicfalcon
from logicfalcon import (
    AutonomousDebuggingService,
    FindingSeverity,
    LocalReviewEngine,
    ReviewConfig,
    ReviewReport,
    __platform__,
    __product__,
    __tagline__,
    __version__,
    build_parser,
    run_cli,
)
from logicfalcon.cli import build_root_parser, run_doctor, run_main


def test_logicfalcon_brand_metadata() -> None:
    assert __product__ == "LogicFalcon"
    assert __platform__ == "AEGIS AI"
    assert __tagline__ == "Fast, precise engineering intelligence."
    assert __version__ == logicfalcon.__version__
    assert logicfalcon.__product__ == "LogicFalcon"
    assert logicfalcon.__platform__ == "AEGIS AI"
    assert logicfalcon.__version__ == __version__


def test_logicfalcon_public_api_exports() -> None:
    assert LocalReviewEngine is not None
    assert ReviewConfig is not None
    assert ReviewReport is not None
    assert FindingSeverity is not None
    assert AutonomousDebuggingService is not None
    assert callable(run_cli)
    assert callable(build_parser)
    assert callable(logicfalcon.review)
    assert callable(logicfalcon.review_diff)
    assert callable(logicfalcon.apply_fix)
    assert callable(logicfalcon.verify_fix)
    assert logicfalcon.ReviewFixEngine is not None
    assert logicfalcon.FindingValidator is not None
    assert logicfalcon.ProposedFix is not None


def test_logicfalcon_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["--version"])
    assert code == 0
    captured = capsys.readouterr()
    assert f"LogicFalcon {__version__}" in captured.out
    assert "powered by AEGIS AI" in captured.out


def test_logicfalcon_cli_help_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["--help"])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage: logicfalcon" in captured.out
    assert "review" in captured.out
    assert "doctor" in captured.out
    assert "Fast, precise engineering intelligence" in captured.out
    assert "Powered by AEGIS AI" in captured.out


def test_logicfalcon_cli_empty_args_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage: logicfalcon" in captured.out


def test_logicfalcon_cli_doctor(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_doctor()
    assert code == 0
    captured = capsys.readouterr()
    assert "LogicFalcon — System Diagnostic & Capability Doctor" in captured.out
    assert "Powered by AEGIS AI" in captured.out
    assert "[PASS] Python Version" in captured.out
    assert "Python AST Static Analyzer" in captured.out
    assert "TypeScript/JavaScript Static Parser" in captured.out
    assert "LogicFalcon CLI is operational" in captured.out


def test_logicfalcon_cli_doctor_via_main(capsys: pytest.CaptureFixture[str]) -> None:
    code = run_main(["doctor"])
    assert code == 0
    captured = capsys.readouterr()
    assert "System diagnostics complete. LogicFalcon CLI is operational" in captured.out


def test_logicfalcon_cli_review_subcommand_dispatch(
    cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = run_main(["review", "--repo", str(cli_fixture_repo), "--format", "json"])
    assert code in (0, 1)
    captured = capsys.readouterr()
    assert "repository_path" in captured.out


def test_logicfalcon_cli_review_direct_flag_dispatch(
    cli_fixture_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = run_main(["--repo", str(cli_fixture_repo), "--format", "json"])
    assert code in (0, 1)
    captured = capsys.readouterr()
    assert "repository_path" in captured.out


def test_logicfalcon_root_parser_build() -> None:
    parser = build_root_parser()
    assert parser.prog == "logicfalcon"
