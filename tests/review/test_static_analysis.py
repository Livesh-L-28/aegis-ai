"""Tests for static analysis adapters (ASTSecurityAdapter, RuffAnalysisAdapter, TypeScriptLanguageAdapter)."""

from packages.review.adapters.ast_security import ASTSecurityAdapter
from packages.review.adapters.ruff_adapter import RuffAnalysisAdapter
from packages.review.adapters.typescript_stub import TypeScriptLanguageAdapter
from packages.review.domain.models import FindingCategory, FindingOrigin, FindingSeverity

DANGEROUS_CODE = """import subprocess
import pickle

def run_untrusted(user_cmd: str):
    eval(user_cmd)  # SEC-001
    subprocess.run(user_cmd, shell=True)  # SEC-002
    pickle.loads(b"data")  # SEC-004

def bad_handler():
    try:
        pass
    except Exception:
        pass  # QUAL-001

api_key = "sk-1234567890abcdef123456"  # SEC-003
"""

CLEAN_CODE = """import json

def calculate_sum(a: int, b: int) -> int:
    \"\"\"Calculates sum safely.\"\"\"
    return a + b
"""


def test_ast_security_adapter_detects_violations() -> None:
    adapter = ASTSecurityAdapter()
    assert adapter.is_available() is True

    findings = adapter.analyze_file("dangerous.py", DANGEROUS_CODE)
    rule_ids = {f.rule_id for f in findings}

    assert "SEC-001" in rule_ids
    assert "SEC-002" in rule_ids
    assert "SEC-003" in rule_ids
    assert "SEC-004" in rule_ids
    assert "QUAL-001" in rule_ids

    # Check origin separation
    sec_finding = next(f for f in findings if f.rule_id == "SEC-001")
    assert sec_finding.origin == FindingOrigin.SECURITY_HEURISTIC
    assert sec_finding.severity == FindingSeverity.CRITICAL

    qual_finding = next(f for f in findings if f.rule_id == "QUAL-001")
    assert qual_finding.origin == FindingOrigin.STATIC_ANALYSIS
    assert qual_finding.category == FindingCategory.QUALITY


def test_ast_security_adapter_clean_code() -> None:
    adapter = ASTSecurityAdapter()
    findings = adapter.analyze_file("clean.py", CLEAN_CODE)
    assert len(findings) == 0


def test_ast_security_adapter_syntax_error() -> None:
    adapter = ASTSecurityAdapter()
    findings = adapter.analyze_file("broken.py", "def broken_syntax(")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-005"
    assert findings[0].severity == FindingSeverity.ERROR


def test_ruff_adapter_disabled_by_default() -> None:
    adapter = RuffAnalysisAdapter()
    # When enabled flag is missing or False, does not invoke subprocess
    findings = adapter.analyze_file("clean.py", "x = 1\n", options={"enabled": False})
    assert len(findings) == 0


def test_ruff_adapter_enabled_finds_lint() -> None:
    adapter = RuffAnalysisAdapter()
    if not adapter.is_available():
        return

    # Code with unused import
    code_with_lint = "import os\nimport sys\n\ndef foo():\n    pass\n"
    findings = adapter.analyze_file("lint.py", code_with_lint, options={"enabled": True})
    assert len(findings) > 0
    assert any("F401" in f.rule_id for f in findings)


def test_typescript_stub_is_unsupported() -> None:
    adapter = TypeScriptLanguageAdapter()
    assert adapter.is_available() is False
    assert adapter.STATUS == "UNSUPPORTED_IN_MILESTONE_1"
    findings = adapter.analyze_file("app.ts", "const x: number = 42;")
    assert len(findings) == 0
