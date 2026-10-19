"""Unit tests for FindingValidator and ReviewFixEngine in LogicFalcon (Phase 3)."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from packages.review.domain.models import (
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    ProposedFix,
    ReviewFinding,
    SourceLocation,
    ValidationStatus,
)
from packages.review.fix_engine import (
    FixApprovalRequiredError,
    FixConflictError,
    FixSyntaxValidationError,
    ReviewFixEngine,
)
from packages.review.validator import FindingValidator


@pytest.fixture
def temp_repo() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        # Create a sample python file
        sample_file = repo_path / "sample.py"
        sample_file.write_text(
            "def process_data(items=[]):\n"
            "    print(items)\n"
            "    return items\n"
        )
        yield repo_path


def test_validator_valid_finding(temp_repo: Path) -> None:
    validator = FindingValidator(repo_root=temp_repo)
    finding = ReviewFinding(
        rule_id="QUAL-002",
        title="Mutable Default Argument",
        message="items=[] is mutable",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.QUALITY,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="sample.py", start_line=1, end_line=1),
        technical_evidence="items=[]",
        confidence=1.0,
        tool_name="ast_security",
    )

    verified, stats = validator.validate([finding])
    assert len(verified) == 1
    assert verified[0].validation_status == ValidationStatus.VALIDATED
    assert stats.validated == 1
    assert stats.rejected_location == 0


def test_validator_path_traversal(temp_repo: Path) -> None:
    validator = FindingValidator(repo_root=temp_repo)
    finding = ReviewFinding(
        rule_id="SEC-001",
        title="Traversal Attempt",
        message="Bad path",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.SECURITY,
        origin=FindingOrigin.HYPOTHESIS,
        location=SourceLocation(file_path="../etc/passwd", start_line=1),
        confidence=0.9,
        tool_name="ai_reviewer",
    )

    verified, stats = validator.validate([finding])
    assert len(verified) == 0
    assert stats.rejected_location == 1


def test_validator_out_of_bounds_line(temp_repo: Path) -> None:
    validator = FindingValidator(repo_root=temp_repo)
    finding = ReviewFinding(
        rule_id="QUAL-001",
        title="Out of Bounds",
        message="Invalid line",
        severity=FindingSeverity.INFO,
        category=FindingCategory.QUALITY,
        origin=FindingOrigin.HYPOTHESIS,
        location=SourceLocation(file_path="sample.py", start_line=999),
        confidence=0.8,
        tool_name="ai_reviewer",
    )

    verified, stats = validator.validate([finding])
    assert len(verified) == 0
    assert stats.rejected_location == 1


def test_validator_deduplication(temp_repo: Path) -> None:
    validator = FindingValidator(repo_root=temp_repo)
    f1 = ReviewFinding(
        rule_id="QUAL-002",
        title="Mutable Default Argument (Heuristic)",
        message="Heuristic finding",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.QUALITY,
        origin=FindingOrigin.HYPOTHESIS,
        location=SourceLocation(file_path="sample.py", start_line=1),
        confidence=0.7,
        tool_name="ai_reviewer",
    )
    f2 = ReviewFinding(
        rule_id="QUAL-002",
        title="Mutable Default Argument (AST)",
        message="AST finding",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.QUALITY,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="sample.py", start_line=1),
        confidence=1.0,
        tool_name="ast_security",
    )

    verified, stats = validator.validate([f1, f2])
    assert len(verified) == 1
    assert stats.deduplicated_dropped == 1
    assert verified[0].confidence == 1.0
    assert verified[0].tool_name == "ast_security"


def test_fix_engine_approval_required(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None):",
        explanation="Use None as default",
    )

    with pytest.raises(FixApprovalRequiredError):
        engine.apply_fix(fix, approved=False)


def test_fix_engine_dry_run(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None):",
    )

    res = engine.apply_fix(fix, dry_run=True)
    assert res.success is True
    assert "process_data(items=None)" in res.diff

    # Verify original file was NOT modified
    content = (temp_repo / "sample.py").read_text()
    assert "items=[]" in content


def test_fix_engine_apply_success(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None):",
        explanation="Safely replace mutable default",
    )

    res = engine.apply_fix(fix, approved=True, create_backup=True)
    assert res.success is True
    assert res.backup_path is not None
    assert Path(res.backup_path).exists()

    new_content = (temp_repo / "sample.py").read_text()
    assert "def process_data(items=None):" in new_content
    assert "items=[]" not in new_content


def test_fix_engine_syntax_error_prevented(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None",  # Missing closing paren -> SyntaxError!
    )

    with pytest.raises(FixSyntaxValidationError):
        engine.apply_fix(fix, approved=True, validate_syntax=True)

    # Content remains untouched
    content = (temp_repo / "sample.py").read_text()
    assert "items=[]" in content


def test_fix_engine_conflict_detected(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def other_function():",  # Does NOT match sample.py line 1
        replacement_code="def other_function_fixed():",
    )

    with pytest.raises(FixConflictError):
        engine.apply_fix(fix, approved=True)


def test_fix_engine_isolated_workspace(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None):",
    )

    temp_ws = engine.apply_in_temp_workspace([fix])
    try:
        # Isolated copy has new content
        assert "def process_data(items=None):" in (temp_ws / "sample.py").read_text()
        # Original remains untouched
        assert "items=[]" in (temp_repo / "sample.py").read_text()
    finally:
        import shutil
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_fix_engine_verify_remediation_success(temp_repo: Path) -> None:
    # Add a test file that imports sample.py
    test_file = temp_repo / "test_sample.py"
    test_file.write_text(
        "import sample\n"
        "def test_func():\n"
        "    assert sample.process_data(None) is None\n"
    )

    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None):",
    )

    res = engine.verify_remediation(
        fixes=[fix],
        run_tests=False,
        run_linters=False,
    )
    assert res.success is True
    assert res.syntax_valid is True
    assert res.fixes_applied == 1


def test_fix_engine_verify_remediation_syntax_failure(temp_repo: Path) -> None:
    engine = ReviewFixEngine(repo_root=temp_repo)
    fix = ProposedFix(
        file_path="sample.py",
        start_line=1,
        end_line=1,
        original_code="def process_data(items=[]):",
        replacement_code="def process_data(items=None",  # Missing closing paren
    )

    # When syntax validation is bypassed during apply, verify_remediation catches it
    res = engine.verify_remediation(
        fixes=[fix],
        run_tests=False,
        run_linters=False,
    )
    assert res.success is False
    assert res.syntax_valid is False
    assert "syntax error" in (res.error_message or "").lower()

