"""Repeatable benchmark and evaluation framework for LogicFalcon code review (Phase 3).

Measures Precision, Recall, F1 Score, False Discovery Rate (FDR), and execution
latency across standardized ground-truth review scenarios.
"""

import time
from dataclasses import dataclass

from packages.review.adapters.ast_security import ASTSecurityAdapter
from packages.review.domain.models import GitDiffSummary, ReviewFinding
from packages.review.git.diff_parser import GitDiffParser
from packages.review.validator import FindingValidator


@dataclass
class BenchmarkCase:
    name: str
    diff_text: str
    expected_rule_ids: set[str]
    is_negative_case: bool = False  # Should produce NO findings


BENCHMARK_CASES: list[BenchmarkCase] = [
    BenchmarkCase(
        name="Hardcoded Secret Detection (SEC-003)",
        diff_text="""diff --git a/app/config.py b/app/config.py
new file mode 100644
--- /dev/null
+++ b/app/config.py
@@ -0,0 +1,3 @@
+api_key = "AKIAIOSFODNN7EXAMPLE"
+def get_key():
+    return api_key
""",
        expected_rule_ids={"SEC-003"},
    ),
    BenchmarkCase(
        name="Insecure Temp File (SEC-006)",
        diff_text="""diff --git a/app/utils.py b/app/utils.py
new file mode 100644
--- /dev/null
+++ b/app/utils.py
@@ -0,0 +1,3 @@
+import tempfile
+def create_temp():
+    return tempfile.mktemp()
""",
        expected_rule_ids={"SEC-006"},
    ),
    BenchmarkCase(
        name="SQL Injection via String Format (SEC-007)",
        diff_text="""diff --git a/app/db.py b/app/db.py
new file mode 100644
--- /dev/null
+++ b/app/db.py
@@ -0,0 +1,3 @@
+def query_user(cursor, username):
+    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
""",
        expected_rule_ids={"SEC-007"},
    ),
    BenchmarkCase(
        name="Mutable Default Argument (QUAL-002)",
        diff_text="""diff --git a/app/models.py b/app/models.py
new file mode 100644
--- /dev/null
+++ b/app/models.py
@@ -0,0 +1,3 @@
+def add_item(item, items=[]):
+    items.append(item)
+    return items
""",
        expected_rule_ids={"QUAL-002"},
    ),
    BenchmarkCase(
        name="Self Comparison (QUAL-003)",
        diff_text="""diff --git a/app/check.py b/app/check.py
new file mode 100644
--- /dev/null
+++ b/app/check.py
@@ -0,0 +1,3 @@
+def is_same(x):
+    return x == x
""",
        expected_rule_ids={"QUAL-003"},
    ),
    BenchmarkCase(
        name="Unmanaged File Resource (QUAL-006)",
        diff_text="""diff --git a/app/io.py b/app/io.py
new file mode 100644
--- /dev/null
+++ b/app/io.py
@@ -0,0 +1,4 @@
+def read_data(path):
+    f = open(path, "r")
+    return f.read()
""",
        expected_rule_ids={"QUAL-006"},
    ),
    BenchmarkCase(
        name="Clean Idiomatic Code — Negative Baseline",
        diff_text="""diff --git a/app/clean.py b/app/clean.py
new file mode 100644
--- /dev/null
+++ b/app/clean.py
@@ -0,0 +1,10 @@
+import tempfile
+
+def safe_query(cursor, username):
+    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
+
+def safe_items(items=None):
+    if items is None:
+        items = []
+    return items
+""",
        expected_rule_ids=set(),
        is_negative_case=True,
    ),
]


def test_evaluation_benchmark_precision_and_recall() -> None:
    """Runs the benchmark suite and asserts CodeRabbit-class precision, recall, and latency."""
    diff_parser = GitDiffParser()
    adapter = ASTSecurityAdapter()
    validator = FindingValidator(min_confidence=0.6, reject_ungrounded=False)

    tp_count = 0
    fp_count = 0
    fn_count = 0

    start_bench = time.perf_counter()

    for case in BENCHMARK_CASES:
        summary: GitDiffSummary = diff_parser.parse(case.diff_text)
        assert len(summary.files) == 1
        cf = summary.files[0]

        # Extract file additions
        added_lines = []
        for hunk in cf.hunks:
            for line in hunk.lines:
                if line.startswith("+") and not line.startswith("+++"):
                    added_lines.append(line[1:])
        source_code = "\n".join(added_lines)

        findings: list[ReviewFinding] = adapter.analyze_file(cf.new_path or "test.py", source_code)
        verified_findings, _ = validator.validate(findings, diff_summary=summary)

        detected_rules = {f.rule_id for f in verified_findings}

        if case.is_negative_case:
            # All detected rules are false positives
            fp_count += len(detected_rules)
        else:
            # Compute True Positives and False Negatives
            for exp in case.expected_rule_ids:
                if exp in detected_rules:
                    tp_count += 1
                else:
                    fn_count += 1
            # Unexpected rules are false positives
            unexpected = detected_rules - case.expected_rule_ids
            fp_count += len(unexpected)

    bench_duration = time.perf_counter() - start_bench

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Verification gates:
    # 1. 100% Recall on standard AST rules
    assert recall >= 0.95, f"Recall {recall:.2f} below threshold (TP={tp_count}, FN={fn_count})"
    # 2. 100% Precision on clean code baseline (no false positives)
    assert precision >= 0.95, f"Precision {precision:.2f} below threshold (TP={tp_count}, FP={fp_count})"
    assert f1 >= 0.95, f"F1 Score {f1:.2f} below threshold"
    assert fp_count == 0, f"Found {fp_count} false positives in benchmark"
    # 3. Latency check: Full benchmark suite executes under 1.0 second
    assert bench_duration < 1.0, f"Benchmark duration {bench_duration:.2f}s exceeded 1.0s target"
