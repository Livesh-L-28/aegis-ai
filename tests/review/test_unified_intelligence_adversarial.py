"""Adversarial and security tests for Unified Engineering Intelligence."""

import tempfile
from pathlib import Path

import pytest

from packages.review.unified.models import (
    RecommendationCategory,
    RecommendationPriority,
    UnifiedIntelligenceReport,
    UnifiedRecommendation,
)
from packages.review.unified.report_generator import UnifiedReportGenerator


def test_adversarial_path_traversal_in_unified_report_write_rejected() -> None:
    rep = UnifiedIntelligenceReport(
        repository_path="/fake/repo",
        repository_id="fake-hash",
    )
    generator = UnifiedReportGenerator(rep)

    with tempfile.TemporaryDirectory() as tmpdir:
        outside_target = Path(tmpdir) / "dir" / ".." / ".." / "escaped.md"
        with pytest.raises(PermissionError):
            generator.write_report(outside_target, "test content", repo_root=tmpdir)


def test_adversarial_source_code_overwrite_defense() -> None:
    rep = UnifiedIntelligenceReport(
        repository_path="/fake/repo",
        repository_id="fake-hash",
    )
    generator = UnifiedReportGenerator(rep)

    with tempfile.TemporaryDirectory() as tmpdir:
        source_file = Path(tmpdir) / "app.py"
        with pytest.raises(PermissionError, match="Refusing to write report to source code file"):
            generator.write_report(source_file, "malicious payload")

        ts_file = Path(tmpdir) / "index.ts"
        with pytest.raises(PermissionError, match="Refusing to write report to source code file"):
            generator.write_report(ts_file, "malicious payload")


def test_adversarial_secret_redaction_across_unified_reports() -> None:
    raw_secret = "ghp_superSecretGitHubToken1234567890abcdef"
    rec = UnifiedRecommendation(
        id="REC-TEST-SECRET",
        priority=RecommendationPriority.CRITICAL,
        category=RecommendationCategory.SECURITY,
        title=f"Secret leak: {raw_secret}",
        rationale=f"Vulnerable token found: {raw_secret}",
        supporting_evidence=[f"Token: {raw_secret}"],
        suggested_action=f"Revoke {raw_secret}",
        confidence=1.0,
    )
    rep = UnifiedIntelligenceReport(
        repository_path=f"/fake/path/{raw_secret}",
        repository_id="fake-hash",
        recommendations=[rec],
    )
    generator = UnifiedReportGenerator(rep)

    json_out = generator.to_json()
    assert raw_secret not in json_out
    assert "[REDACTED_TOKEN]" in json_out

    md_out = generator.to_markdown()
    assert raw_secret not in md_out
    assert "[REDACTED_TOKEN]" in md_out

    text_out = generator.to_text()
    assert raw_secret not in text_out
    assert "[REDACTED_TOKEN]" in text_out
