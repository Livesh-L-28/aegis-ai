"""Regression tests for SEC-01: Path traversal and boundary containment."""

import os
from pathlib import Path

from packages.review.engine import LocalReviewEngine
from packages.review.security.path_validation import validate_contained_path


def test_validate_contained_path_boundaries(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_secret = outside / "secret.py"
    outside_secret.write_text("HOST_SECRET_TOKEN = 'shhh'")

    # In-repo files
    valid_file = repo / "valid.py"
    valid_file.write_text("print('hello')")

    # 1. Reject absolute paths
    assert validate_contained_path(repo, "/etc/hosts") is None
    assert validate_contained_path(repo, "//etc/hosts") is None

    # 2. Reject relative traversal
    assert validate_contained_path(repo, "../../outside/secret.py") is None
    assert validate_contained_path(repo, "pkg/../../../outside/secret.py") is None

    # 3. Reject symlink escaping repo root
    escape_link = repo / "escape_link"
    os.symlink(str(outside), str(escape_link))
    assert validate_contained_path(repo, "escape_link/secret.py") is None

    # 4. Accept valid in-repo path
    assert validate_contained_path(repo, "valid.py") == valid_file.resolve()

    # 5. Accept internal symlink
    internal_dir = repo / "internal"
    internal_dir.mkdir()
    internal_target = internal_dir / "target.py"
    internal_target.write_text("TARGET")
    internal_link = repo / "internal_link"
    os.symlink(str(internal_dir), str(internal_link))
    assert validate_contained_path(repo, "internal_link/target.py") == internal_target.resolve()

    # 6. Non-existent path inside repo resolves safely but does not exist
    nonexistent = validate_contained_path(repo, "nonexistent.py")
    assert nonexistent == (repo / "nonexistent.py").resolve()
    assert not nonexistent.is_file()

    # 7. Non-existent path outside repo is rejected
    assert validate_contained_path(repo, "../../nonexistent.py") is None


def test_review_diff_blocks_arbitrary_host_file_read(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "confidential.py"
    secret.write_text("HOST_DISK_SECRET = 'sensitive_host_secret_9988'")

    # Malicious diff targeting outside file via traversal
    malicious_diff = """diff --git a/../../outside/confidential.py b/../../outside/confidential.py
--- a/../../outside/confidential.py
+++ b/../../outside/confidential.py
@@ -1,1 +1,2 @@
+NEW_LINE = 1
"""

    engine = LocalReviewEngine(repo_root=repo)
    report = engine.review_diff(malicious_diff)

    # Must not have reviewed or read the outside file
    assert len(report.files_reviewed) == 0
    assert any("Rejected path outside repository boundary" in err for err in report.errors)

    # Prove that confidential content was never loaded into findings or report
    report_json = report.model_dump_json()
    assert "sensitive_host_secret_9988" not in report_json
