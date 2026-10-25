"""Tests for LocalReviewEngine end-to-end local review."""

import tempfile
from pathlib import Path

from packages.review.domain.models import FindingSeverity
from packages.review.engine import LocalReviewEngine, ReviewConfig

RAW_DIFF = """diff --git a/src/processor.py b/src/processor.py
new file mode 100644
--- /dev/null
+++ b/src/processor.py
@@ -0,0 +1,6 @@
+def execute_user_query(query: str):
+    eval(query)
+    return True
+
+def safe_func():
+    return 42
"""


def test_review_diff_detects_violations_and_symbols() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_root = Path(tmp_dir)
        engine = LocalReviewEngine(repo_root=repo_root)

        report = engine.review_diff(RAW_DIFF)

        assert report.is_clean is False
        assert len(report.findings) >= 1
        eval_finding = next(f for f in report.findings if f.rule_id == "SEC-001")
        assert eval_finding.severity == FindingSeverity.CRITICAL
        assert eval_finding.location.file_path == "src/processor.py"

        # Check changed symbols
        assert len(report.affected_artifacts.changed_symbols) >= 1
        sym_names = [cs.symbol.name for cs in report.affected_artifacts.changed_symbols]
        assert "execute_user_query" in sym_names


def test_review_engine_skips_large_files() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_root = Path(tmp_dir)
        large_file = repo_root / "huge.py"
        large_file.write_text("#" * 500, encoding="utf-8")

        config = ReviewConfig(max_file_size_bytes=100)
        engine = LocalReviewEngine(repo_root=repo_root, config=config)

        diff = """diff --git a/huge.py b/huge.py
index 1111..2222 100644
--- a/huge.py
+++ b/huge.py
@@ -1,1 +1,2 @@
 #
+# extra
"""
        report = engine.review_diff(diff)
        # Should record an informational finding about file size limit
        assert any(f.rule_id == "RESOURCE-LIMIT" for f in report.findings)


def test_review_engine_ignores_configured_patterns() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_root = Path(tmp_dir)
        engine = LocalReviewEngine(repo_root=repo_root)

        diff = """diff --git a/.venv/lib/package.py b/.venv/lib/package.py
new file mode 100644
--- /dev/null
+++ b/.venv/lib/package.py
@@ -0,0 +1,2 @@
+eval("secret")
"""
        report = engine.review_diff(diff)
        # Ignored .venv path should produce no findings
        assert len(report.findings) == 0
        assert len(report.files_reviewed) == 0


def test_review_local_git_diff_smoke(cli_fixture_repo: Path) -> None:
    # Smoke test on an isolated git fixture repository
    engine = LocalReviewEngine(repo_root=cli_fixture_repo)
    report = engine.review_local_git_diff()
    assert report.repository_path != ""
    assert isinstance(report.findings, list)
    assert report.execution_time_seconds >= 0.0
