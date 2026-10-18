"""Tests for the secure GitDiffParser."""

from packages.review.domain.models import DiffChangeType
from packages.review.git.diff_parser import GitDiffParser

SAMPLE_DIFF = """commit a1b2c3d4e5f6
Author: Developer <dev@example.com>
Date:   Mon Oct 18 10:00:00 2026

diff --git a/packages/service.py b/packages/service.py
index 1111111..2222222 100644
--- a/packages/service.py
+++ b/packages/service.py
@@ -10,6 +10,8 @@ def existing_function():
     pass

+def added_function():
+    return True
+
 def another_function():
     pass
diff --git a/docs/README.md b/docs/README.md
new file mode 100644
--- /dev/null
+++ b/docs/README.md
@@ -0,0 +1,3 @@
+# New Documentation
+Line 1
+Line 2
diff --git a/legacy/old_tool.py b/legacy/old_tool.py
deleted file mode 100644
--- a/legacy/old_tool.py
+++ /dev/null
@@ -1,5 +0,0 @@
-def legacy():
-    pass
diff --git a/config/old_name.json b/config/new_name.json
similarity index 100%
rename from config/old_name.json
rename to config/new_name.json
diff --git a/assets/logo.png b/assets/logo.png
index 3333333..4444444 100644
Binary files a/assets/logo.png and b/assets/logo.png differ
"""


def test_diff_parser_extracts_commits_and_files() -> None:
    parser = GitDiffParser()
    summary = parser.parse(SAMPLE_DIFF)

    assert summary.head_commit == "a1b2c3d4e5f6"
    assert summary.base_commit == "1111111"
    assert len(summary.files) == 5

    # Check modified file
    f0 = summary.files[0]
    assert f0.old_path == "packages/service.py"
    assert f0.new_path == "packages/service.py"
    assert f0.change_type == DiffChangeType.MODIFIED
    assert len(f0.hunks) == 1
    assert 13 in f0.hunks[0].added_lines
    assert 14 in f0.hunks[0].added_lines

    # Check added file
    f1 = summary.files[1]
    assert f1.old_path is None
    assert f1.new_path == "docs/README.md"
    assert f1.change_type == DiffChangeType.ADDED
    assert f1.added_lines_count == 3

    # Check deleted file
    f2 = summary.files[2]
    assert f2.old_path == "legacy/old_tool.py"
    assert f2.new_path is None
    assert f2.change_type == DiffChangeType.DELETED
    assert f2.deleted_lines_count == 2
    assert f2.hunks[0].old_length == 5

    # Check renamed file
    f3 = summary.files[3]
    assert f3.old_path == "config/old_name.json"
    assert f3.new_path == "config/new_name.json"
    assert f3.change_type == DiffChangeType.RENAMED

    # Check binary file
    f4 = summary.files[4]
    assert f4.is_binary is True
    assert f4.change_type == DiffChangeType.BINARY


def test_diff_parser_handles_empty_and_malformed() -> None:
    parser = GitDiffParser()

    # Empty
    empty_summary = parser.parse("")
    assert len(empty_summary.files) == 0
    assert empty_summary.total_added_lines == 0

    # Malformed text
    malformed = "This is not a git diff at all\nRandom text line 2"
    summary = parser.parse(malformed)
    assert len(summary.files) == 0
    assert len(summary.warnings) == 0


def test_diff_parser_size_truncation() -> None:
    parser = GitDiffParser(max_diff_bytes=50)
    large_diff = "diff --git a/file.py b/file.py\n" + ("+line\n" * 20)
    summary = parser.parse(large_diff)
    assert summary.is_truncated is True
    assert len(summary.warnings) > 0
