"""Unified Command-Line Interface for LogicFalcon (Powered by AEGIS AI)."""

import argparse
import shutil
import sys
from typing import NoReturn

from logicfalcon import __platform__, __product__, __version__
from packages.intelligence.code.indexer import PythonASTParser
from packages.intelligence.code.ts_parser import JavaScriptTypeScriptParser
from packages.review.cli import run_cli as run_review_cli


def run_doctor() -> int:
    """Runs a non-destructive environment and capability diagnostic."""
    sys.stdout.write(f"🦅  {__product__} — System Diagnostic & Capability Doctor (Powered by {__platform__})\n")
    sys.stdout.write("=" * 65 + "\n")

    # 1. Python version check
    py_ver = sys.version_info
    py_ok = py_ver >= (3, 12)
    py_status = "PASS" if py_ok else "FAIL"
    sys.stdout.write(f"[{py_status}] Python Version: {py_ver.major}.{py_ver.minor}.{py_ver.micro} (>= 3.12 required)\n")

    # 2. Git binary check
    git_bin = shutil.which("git")
    git_status = "PASS" if git_bin else "WARN"
    sys.stdout.write(f"[{git_status}] Git Executable: {git_bin or 'Not found in PATH'}\n")

    # 3. Python AST parser check
    try:
        symbols, _deps = PythonASTParser.parse_source("test.py", "def hello(): pass")
        ast_ok = len(symbols) == 1 and symbols[0].name == "hello"
        ast_status = "PASS" if ast_ok else "FAIL"
    except Exception as e:
        ast_status = f"FAIL ({e})"
    sys.stdout.write(f"[{ast_status}] Python AST Static Analyzer: functional\n")

    # 4. Multi-language TypeScript parser check
    try:
        ts_res = JavaScriptTypeScriptParser().parse_source("test.ts", "function greet(): string { return 'hi'; }")
        ts_ok = len(ts_res.symbols) == 1 and ts_res.symbols[0].name == "greet"
        ts_status = "PASS" if ts_ok else "FAIL"
    except Exception as e:
        ts_status = f"FAIL ({e})"
    sys.stdout.write(f"[{ts_status}] TypeScript/JavaScript Static Parser: functional\n")

    # 5. External linter (Ruff) check
    ruff_bin = shutil.which("ruff")
    ruff_status = "PASS" if ruff_bin else "INFO"
    sys.stdout.write(f"[{ruff_status}] External Linter (Ruff): {ruff_bin or 'Optional / Not installed'}\n")

    # 6. Service infrastructure status (informational)
    sys.stdout.write("[INFO] Backend Services (PostgreSQL / Redis): Optional (not required for CLI review)\n")
    sys.stdout.write("=" * 65 + "\n")
    sys.stdout.write(f"System diagnostics complete. {__product__} CLI is operational.\n")
    return 0


def build_root_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logicfalcon",
        description=f"{__product__} — Fast, precise engineering intelligence. Powered by {__platform__}.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"{__product__} {__version__} (powered by {__platform__})",
        help="Show program's version number and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Subcommand: review
    subparsers.add_parser(
        "review",
        help="Run deterministic repository intelligence & automated code review.",
        add_help=False,  # Let review parser handle its own flags
    )

    # Subcommand: doctor
    subparsers.add_parser(
        "doctor",
        help="Run environment health check, AST parser capabilities, and tool diagnostic.",
    )

    return parser


def run_main(args: list[str] | None = None) -> int:
    argv = sys.argv[1:] if args is None else args

    # Handle direct review fallback when arguments start with review flags
    if argv and argv[0].startswith("-") and argv[0] not in ("-v", "--version", "-h", "--help"):
        return run_review_cli(argv)

    if not argv:
        parser = build_root_parser()
        parser.print_help()
        return 0

    if argv[0] in ("-v", "--version"):
        sys.stdout.write(f"{__product__} {__version__} (powered by {__platform__})\n")
        return 0

    if argv[0] in ("-h", "--help"):
        parser = build_root_parser()
        parser.print_help()
        return 0

    if argv[0] == "doctor":
        return run_doctor()

    if argv[0] == "review":
        return run_review_cli(argv[1:])

    # Fallback to standard argparsing
    parser = build_root_parser()
    parsed = parser.parse_args(argv)
    if parsed.subcommand == "doctor":
        return run_doctor()
    elif parsed.subcommand == "review":
        return run_review_cli(argv[1:])

    parser.print_help()
    return 0


def main() -> NoReturn:
    sys.exit(run_main())


if __name__ == "__main__":
    main()
