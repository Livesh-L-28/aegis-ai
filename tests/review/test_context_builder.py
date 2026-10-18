"""Tests for ContextBuilder bounding and prompt construction."""

from packages.review.ai.context_builder import ContextBuilder
from packages.review.domain.models import (
    AffectedArtifacts,
    ChangedFile,
    DiffChangeType,
    DiffHunk,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    ReviewFinding,
    SourceLocation,
)


def test_context_builder_bounds_character_size() -> None:
    builder = ContextBuilder(max_total_chars=500, max_hunk_lines_per_file=50)

    # Large diff hunk
    lines = [f"+line_number_{i} = 'some_data_value'" for i in range(100)]
    hunk = DiffHunk(
        old_start=1,
        old_length=0,
        new_start=1,
        new_length=100,
        lines=lines,
        added_lines=list(range(1, 101)),
    )
    cf = ChangedFile(
        new_path="large_module.py",
        change_type=DiffChangeType.ADDED,
        hunks=[hunk],
        added_lines_count=100,
    )

    context = builder.build_context(
        repository_name="test_repo",
        changed_files=[cf],
        affected_artifacts=AffectedArtifacts(),
        static_findings=[],
    )

    assert context.is_truncated is True
    assert context.total_character_count <= 600
    assert any("partially omitted" in note for note in context.missing_context_notes)


def test_context_builder_includes_static_findings_summary() -> None:
    builder = ContextBuilder()
    finding = ReviewFinding(
        rule_id="SEC-001",
        title="Eval usage",
        message="Dangerous eval()",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.SECURITY,
        origin=FindingOrigin.SECURITY_HEURISTIC,
        location=SourceLocation(file_path="app.py", start_line=10),
        tool_name="ast_security",
    )

    context = builder.build_context(
        repository_name="test_repo",
        changed_files=[],
        affected_artifacts=AffectedArtifacts(),
        static_findings=[finding],
    )

    assert len(context.static_findings_summary) == 1
    assert context.static_findings_summary[0]["rule_id"] == "SEC-001"
