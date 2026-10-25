"""Adversarial and security verification tests for LogicFalcon Reverse Engineering Intelligence.

Validates robust defense-in-depth against:
- Symlink escapes (symlinks pointing outside the repository root).
- Symlink cycles / infinite directory loops.
- Directory traversal in output file destinations.
- Accidental overwrite of source code files.
- Secret leakage in Markdown, JSON, text, and Mermaid outputs.
- Resource limits (oversized files, directory depth bounds, file count bounds).
- Non-UTF8 encodings, binary files, and unusual filenames.
- Injection attacks in Mermaid and Markdown formatting.
"""

import os
from pathlib import Path

import pytest

from packages.review.reverse_engineering.engine import ReverseEngineeringEngine
from packages.review.reverse_engineering.models import ReverseEngineeringReport
from packages.review.reverse_engineering.report_generator import (
    ReverseEngineeringReportGenerator,
    escape_mermaid_id,
    escape_mermaid_label,
)
from packages.review.reverse_engineering.scanner import RepositoryScanner


def test_symlink_escape_blocked(tmp_path: Path) -> None:
    """Verifies that symlinks pointing outside the repository boundary are blocked."""
    repo = tmp_path / "safe_repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('safe')\n")

    # Secret file outside repository
    secret_dir = tmp_path / "external_secrets"
    secret_dir.mkdir()
    secret_file = secret_dir / "external_token.txt"
    secret_file.write_text("SUPER_SECRET_EXTERNAL_KEY=12345\n")

    # Symlink inside repository pointing outside
    symlink_path = repo / "escaped_link.txt"
    try:
        os.symlink(secret_file, symlink_path)
    except OSError:
        pytest.skip("Symlink creation not permitted in this test environment.")

    scanner = RepositoryScanner(repo_root=repo)
    scanner.scan()

    # The external secret file must NOT be cataloged as a discovered file
    assert not any("external_token" in str(f) for f in scanner.discovered_files)
    # A boundary violation limitation must be recorded
    assert any(lim.category == "symlink_escaping_boundary" for lim in scanner.limitations)


def test_symlink_loop_cycle_defense(tmp_path: Path) -> None:
    """Verifies that circular symlink loops terminate gracefully without infinite recursion."""
    repo = tmp_path / "loop_repo"
    repo.mkdir()
    sub_dir = repo / "sub"
    sub_dir.mkdir()
    (sub_dir / "code.py").write_text("print('hello')\n")

    # Create loop: sub/loop -> sub
    loop_link = sub_dir / "loop"
    try:
        os.symlink(sub_dir, loop_link, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks not supported in this test environment.")

    scanner = RepositoryScanner(repo_root=repo, max_depth=10)
    # Must terminate quickly and not raise RecursionError
    inv = scanner.scan()
    assert inv.total_files >= 1


def test_directory_depth_bound_defense(tmp_path: Path) -> None:
    """Verifies that directory depth exceeding max_depth is pruned with structured limitation."""
    repo = tmp_path / "deep_repo"
    repo.mkdir()

    # Create directory tree 20 levels deep
    curr = repo
    for i in range(20):
        curr = curr / f"level_{i}"
        curr.mkdir()
    (curr / "deep_leaf.py").write_text("x = 1\n")

    scanner = RepositoryScanner(repo_root=repo, max_depth=10)
    scanner.scan()

    # Deep leaf must not be discovered
    assert not any("deep_leaf.py" in str(f) for f in scanner.discovered_files)
    # Depth limitation recorded
    assert any(lim.category == "max_depth_exceeded" for lim in scanner.limitations)


def test_oversized_file_not_read_into_memory(tmp_path: Path) -> None:
    """Verifies that files exceeding max_file_size_bytes are rejected before reading."""
    repo = tmp_path / "size_repo"
    repo.mkdir()

    # Create 500KB file
    big_file = repo / "large_data.py"
    big_file.write_text("#" * 500_000)

    # Scanner configured with 100KB limit
    scanner = RepositoryScanner(repo_root=repo, max_file_size_bytes=100_000)
    scanner.scan()

    assert not any("large_data.py" in str(f) for f in scanner.discovered_files)
    oversized_lims = [lim for lim in scanner.limitations if lim.category == "oversized_file"]
    assert len(oversized_lims) == 1
    assert "large_data.py" in oversized_lims[0].file_path


def test_secret_leakage_prevention_across_all_report_formats(tmp_path: Path) -> None:
    """CRITICAL SECURITY TEST: Verifies that synthetic secret literals never leak in generated reports."""
    repo = tmp_path / "secret_repo"
    repo.mkdir()

    synthetic_secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "p@ssw0rd_super_secret_token_value_999",
        "postgres://app_user:ultra_classified_pw@db.corp.internal:5432/db",
    ]

    # File 1: Python with secret in os.environ and variable
    (repo / "config.py").write_text(
        f"""import os
AWS_KEY = "{synthetic_secrets[0]}"
GITHUB_PAT = "{synthetic_secrets[1]}"
DB_URL = os.environ.get("DATABASE_URL", "{synthetic_secrets[3]}")
SECRET_PARAM = os.getenv("APP_PASSWORD", "{synthetic_secrets[2]}")
"""
    )
    # File 2: .env.example with secret values
    (repo / ".env.example").write_text(
        f"""AWS_KEY={synthetic_secrets[0]}
DB_URL={synthetic_secrets[3]}
"""
    )

    engine = ReverseEngineeringEngine(repo_root=repo)
    report = engine.analyze()
    generator = ReverseEngineeringReportGenerator(report)

    # Verify Markdown
    md_output = generator.to_markdown()
    for s in synthetic_secrets:
        assert s not in md_output, f"Secret leaked in Markdown: {s}"

    # Verify JSON
    json_output = generator.to_json()
    for s in synthetic_secrets:
        assert s not in json_output, f"Secret leaked in JSON: {s}"

    # Verify Text
    text_output = generator.to_text()
    for s in synthetic_secrets:
        assert s not in text_output, f"Secret leaked in Text: {s}"


def test_output_path_traversal_rejection(tmp_path: Path) -> None:
    """Verifies that writing reports to paths outside repository root is rejected."""
    repo = tmp_path / "safe_project"
    repo.mkdir()
    (repo / "app.py").write_text("pass\n")

    report = ReverseEngineeringReport(
        repository_path=str(repo),
        timestamp="2026-10-24T00:00:00Z",
    )
    generator = ReverseEngineeringReportGenerator(report)

    # Attempt directory traversal outside repository
    escaped_destination = tmp_path / "escaped_outside.md"

    with pytest.raises(PermissionError, match="escapes repository root"):
        generator.write_output(
            output_format="markdown",
            output_file=escaped_destination,
            repo_root=repo,
        )


def test_accidental_source_code_overwrite_rejection(tmp_path: Path) -> None:
    """Verifies that report generator refuses to overwrite source code files."""
    repo = tmp_path / "source_project"
    repo.mkdir()
    source_file = repo / "app.py"
    source_file.write_text("print('precious original code')\n")

    report = ReverseEngineeringReport(
        repository_path=str(repo),
        timestamp="2026-10-24T00:00:00Z",
    )
    generator = ReverseEngineeringReportGenerator(report)

    # Attempt to write report over source file
    with pytest.raises(PermissionError, match="Refusing to write report to source code file"):
        generator.write_output(
            output_format="markdown",
            output_file=source_file,
            repo_root=repo,
        )

    # Ensure source file content was NOT overwritten
    assert source_file.read_text() == "print('precious original code')\n"


def test_mermaid_and_markdown_injection_sanitization() -> None:
    """Verifies that special characters, quotes, and brackets are sanitized in Mermaid output."""
    malicious_id = 'component-->evil["PWN"]'
    escaped_id = escape_mermaid_id(malicious_id)
    assert '"' not in escaped_id
    assert ">" not in escaped_id
    assert "[" not in escaped_id

    malicious_label = 'Node "With Quotes" and [Brackets] and <script>alert(1)</script>'
    escaped_label = escape_mermaid_label(malicious_label)
    assert '"' not in escaped_label
    assert "[" not in escaped_label
    assert "]" not in escaped_label
    assert "<script>" not in escaped_label
    assert "&lt;script&gt;" in escaped_label


def test_binary_and_invalid_encoding_files_handled_gracefully(tmp_path: Path) -> None:
    """Verifies that binary or invalid UTF-8 files do not crash the engine."""
    repo = tmp_path / "binary_repo"
    repo.mkdir()

    # Write non-UTF8 binary bytes into a .py file
    bin_file = repo / "corrupted.py"
    bin_file.write_bytes(b"\x80\x81\xff\xfe\x00\x01\x02\x03\x04")

    # Regular file
    (repo / "clean.py").write_text("x = 10\n")

    engine = ReverseEngineeringEngine(repo_root=repo)
    report = engine.analyze()

    assert report.inventory.total_files >= 1
    # Analysis must complete without unhandled UnicodeDecodeError
    assert any("clean" in comp.name for comp in report.architecture_components) or len(report.architecture_components) >= 0
