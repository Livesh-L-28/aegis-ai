"""Security, Privacy, and Reliability verification tests for LogicFalcon."""

import tempfile
from pathlib import Path

import pytest

from logicfalcon.sdk import apply_fix
from packages.review.domain.models import FindingSeverity, ProposedFix
from packages.review.engine import LocalReviewEngine, ReviewConfig
from packages.review.fix_engine import FixApprovalRequiredError
from packages.review.security.path_validation import validate_contained_path


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_path_traversal_rejection(repo_root: Path) -> None:
    """Verifies that paths attempting to escape repository root are strictly blocked."""
    outside_path = "../../../../../etc/passwd"
    contained = validate_contained_path(repo_root, outside_path)
    assert contained is None, "Path traversal must return None"

    # Engine review must reject and record error
    engine = LocalReviewEngine(repo_root=repo_root)
    report = engine.review_file(outside_path)
    assert any("outside repository boundary" in err for err in report.errors)
    assert len(report.findings) == 0


def test_symlink_escaping_boundary_rejected(repo_root: Path) -> None:
    """Verifies that symlinks pointing outside the repository root are rejected."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        outside_file = tmp_path / "secret.py"
        outside_file.write_text("API_KEY = 'secret123'\n")

        link_inside = repo_dir / "link_to_outside.py"
        try:
            link_inside.symlink_to(outside_file)
        except OSError:
            pytest.skip("Symlink creation not supported on this platform/user")

        contained = validate_contained_path(repo_dir, "link_to_outside.py")
        assert contained is None, "Symlink resolving outside repo boundary must be rejected"


def test_safe_fix_application_requires_approval(repo_root: Path) -> None:
    """Verifies that automated code remediations never modify disk without explicit approval."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir)
        target = tmp_repo / "test_module.py"
        target.write_text("def run(val=[]):\n    pass\n")

        fix = ProposedFix(
            file_path="test_module.py",
            start_line=1,
            end_line=1,
            replacement_code="def run(val=None):",
            explanation="Fix mutable default",
        )

        # 1. Attempting without approval must raise FixApprovalRequiredError
        with pytest.raises(FixApprovalRequiredError):
            apply_fix(fix=fix, approved=False, repo_root=tmp_repo, dry_run=False)

        # Verify disk was NOT modified
        assert target.read_text() == "def run(val=[]):\n    pass\n"

        # 2. Dry run with approved=False succeeds in generating diff preview without writing
        res_preview = apply_fix(fix=fix, approved=False, repo_root=tmp_repo, dry_run=True)
        assert res_preview.success is True
        assert "diff" in res_preview.__dict__
        assert target.read_text() == "def run(val=[]):\n    pass\n"

        # 3. Explicit approval modifies disk safely and creates backup
        res_applied = apply_fix(fix=fix, approved=True, repo_root=tmp_repo, dry_run=False)
        assert res_applied.success is True
        assert target.read_text() == "def run(val=None):\n    pass\n"
        assert res_applied.backup_path is not None
        assert Path(res_applied.backup_path).is_file()


def test_resource_limit_large_file_skip(repo_root: Path) -> None:
    """Verifies that files exceeding configured size limits do not exhaust memory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir)
        large_file = tmp_repo / "huge_payload.py"
        # Write 200 KB
        large_file.write_text("#" * 200_000)

        # Set limit to 50 KB
        config = ReviewConfig(max_file_size_bytes=50_000)
        engine = LocalReviewEngine(repo_root=tmp_repo, config=config)

        report = engine.review_file("huge_payload.py")
        assert len(report.findings) == 1
        assert report.findings[0].rule_id == "RESOURCE-LIMIT"
        assert "exceeds limit" in report.findings[0].message


def test_unsafe_yaml_deserialization_rule(repo_root: Path) -> None:
    """Verifies that unsafe yaml.load calls are flagged and safe_load is accepted."""
    engine = LocalReviewEngine(repo_root=repo_root)

    # Positive test: yaml.load without safe loader
    pos_report = engine.review_files(
        file_paths=["dummy_yaml.py"],
        override_contents={"dummy_yaml.py": "import yaml\ndata = yaml.load(raw_data)\n"},
    )
    yaml_findings = [f for f in pos_report.findings if f.rule_id == "SEC-008"]
    assert len(yaml_findings) == 1
    assert "Insecure YAML Deserialization" in yaml_findings[0].title
    assert yaml_findings[0].severity == FindingSeverity.CRITICAL

    # Negative test: yaml.safe_load
    neg_report = engine.review_files(
        file_paths=["safe_yaml.py"],
        override_contents={"safe_yaml.py": "import yaml\ndata = yaml.safe_load(raw_data)\n"},
    )
    assert not any(f.rule_id == "SEC-008" for f in neg_report.findings)


def test_insecure_archive_extraction_rule(repo_root: Path) -> None:
    """Verifies that archive extraction without safe filters is flagged (Zip Slip / Tarbomb)."""
    engine = LocalReviewEngine(repo_root=repo_root)

    # Positive test: tar.extractall()
    pos_report = engine.review_files(
        file_paths=["dummy_tar.py"],
        override_contents={"dummy_tar.py": "import tarfile\nwith tarfile.open('a.tar') as t:\n    t.extractall()\n"},
    )
    tar_findings = [f for f in pos_report.findings if f.rule_id == "SEC-009"]
    assert len(tar_findings) == 1
    assert tar_findings[0].severity == FindingSeverity.ERROR

    # Negative test: tar.extractall(filter='data')
    neg_report = engine.review_files(
        file_paths=["safe_tar.py"],
        override_contents={"safe_tar.py": "import tarfile\nwith tarfile.open('a.tar') as t:\n    t.extractall(filter='data')\n"},
    )
    assert not any(f.rule_id == "SEC-009" for f in neg_report.findings)


def test_missing_network_timeout_rule(repo_root: Path) -> None:
    """Verifies that HTTP requests without explicit timeouts are flagged."""
    engine = LocalReviewEngine(repo_root=repo_root)

    # Positive test: requests.get without timeout
    pos_report = engine.review_files(
        file_paths=["dummy_req.py"],
        override_contents={"dummy_req.py": "import requests\nresp = requests.get('https://example.com')\n"},
    )
    req_findings = [f for f in pos_report.findings if f.rule_id == "REL-002"]
    assert len(req_findings) == 1
    assert "Missing Timeout" in req_findings[0].title

    # Negative test: requests.get with timeout
    neg_report = engine.review_files(
        file_paths=["safe_req.py"],
        override_contents={"safe_req.py": "import requests\nresp = requests.get('https://example.com', timeout=10.0)\n"},
    )
    assert not any(f.rule_id == "REL-002" for f in neg_report.findings)


def test_secret_redaction_guarantee(repo_root: Path) -> None:
    """Verifies that secret tokens are never exposed in plaintext findings."""
    from packages.review.adapters.ast_security import redact_secrets_in_text

    secret_raw = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    code_line = f"API_KEY = '{secret_raw}'\n"

    redacted = redact_secrets_in_text(code_line)
    assert secret_raw not in redacted
    assert "[REDACTED_SECRET]" in redacted

    engine = LocalReviewEngine(repo_root=repo_root)
    report = engine.review_files(
        file_paths=["credentials.py"],
        override_contents={"credentials.py": code_line},
    )
    sec_findings = [f for f in report.findings if f.rule_id == "SEC-003"]
    assert len(sec_findings) == 1
    # Ensure plaintext secret is NEVER present in the finding representation or message
    finding_str = str(sec_findings[0].model_dump())
    assert secret_raw not in finding_str


def test_dependency_vulnerability_advisory(repo_root: Path) -> None:
    """Verifies offline detection of vulnerable pinned dependencies."""
    from packages.review.adapters.dependency_advisory import DependencyAdvisoryAdapter

    adapter = DependencyAdvisoryAdapter()

    # Positive test: pinned vulnerable version
    vuln_reqs = "requests==2.28.1\nflask>=2.0.0\n"
    findings = adapter.analyze_file("requirements.txt", vuln_reqs)
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP-001"
    assert "requests" in findings[0].title
    assert "CVE-2023-32681" in findings[0].title
    assert findings[0].proposed_fix is not None
    assert "2.31.0" in findings[0].proposed_fix.replacement_code

    # Negative test: safe version
    safe_reqs = "requests==2.31.0\n"
    safe_findings = adapter.analyze_file("requirements.txt", safe_reqs)
    assert len(safe_findings) == 0


def test_command_execution_os_system_and_popen(repo_root: Path) -> None:
    """Verifies that os.system and os.popen calls are flagged under SEC-002."""
    from packages.review.adapters.ast_security import ASTSecurityAdapter

    adapter = ASTSecurityAdapter()
    code_vuln = (
        "import os\n"
        "os.system('rm -rf ' + user_input)\n"
        "stream = os.popen('ls ' + user_input)\n"
    )
    findings = adapter.analyze_file("cmd_exec.py", code_vuln)
    cmd_findings = [f for f in findings if f.rule_id == "SEC-002"]
    assert len(cmd_findings) == 2
    assert any("os.system" in f.title for f in cmd_findings)
    assert any("os.popen" in f.title for f in cmd_findings)


def test_unsafe_deserialization_marshal_and_shelve(repo_root: Path) -> None:
    """Verifies that marshal.loads and shelve.open calls are flagged under SEC-004."""
    from packages.review.adapters.ast_security import ASTSecurityAdapter

    adapter = ASTSecurityAdapter()
    code_vuln = (
        "import marshal\n"
        "import shelve\n"
        "obj = marshal.loads(raw_bytes)\n"
        "db = shelve.open(filename)\n"
    )
    findings = adapter.analyze_file("deserialization.py", code_vuln)
    deser_findings = [f for f in findings if f.rule_id == "SEC-004"]
    assert len(deser_findings) == 2
    assert any("marshal" in f.title.lower() for f in deser_findings)
    assert any("shelve" in f.title.lower() for f in deser_findings)



def test_package_json_advisory_detection() -> None:
    """Verifies polyglot dependency advisory detection in package.json."""
    from packages.review.adapters.dependency_advisory import DependencyAdvisoryAdapter

    adapter = DependencyAdvisoryAdapter()
    pkg_json = """{
  "name": "sample-web",
  "dependencies": {
    "lodash": "4.17.20",
    "axios": "^0.21.0",
    "react": "18.2.0"
  }
}"""
    findings = adapter.analyze_file("package.json", pkg_json)
    assert len(findings) == 2
    lodash_finding = next(f for f in findings if "lodash" in f.title)
    axios_finding = next(f for f in findings if "axios" in f.title)

    assert lodash_finding.rule_id == "DEP-001"
    assert "CVE-2021-23337" in lodash_finding.title
    assert lodash_finding.proposed_fix is not None
    assert "4.17.21" in lodash_finding.proposed_fix.replacement_code

    assert axios_finding.rule_id == "DEP-001"
    assert "CVE-2021-3749" in axios_finding.title


def test_analyzer_registry_contract() -> None:
    """Verifies custom adapter registration, retrieval, and validation in AnalyzerRegistry."""
    from packages.review.adapters.base import AnalyzerRegistry, StaticAnalysisAdapter
    from packages.review.domain.models import ReviewFinding

    registry = AnalyzerRegistry()

    class CustomLinter(StaticAnalysisAdapter):
        @property
        def name(self) -> str:
            return "custom_linter"

        def is_available(self) -> bool:
            return True

        def analyze_file(
            self,
            file_path: str,
            content: str,
            options: dict[str, object] | None = None,
        ) -> list[ReviewFinding]:
            return []

    adapter = CustomLinter()
    registry.register(adapter)
    assert registry.get("custom_linter") is adapter
    assert "custom_linter" in registry.list_adapters()
    assert adapter in registry.get_all()

    # Rejection of invalid types
    with pytest.raises(TypeError, match="must inherit from StaticAnalysisAdapter"):
        registry.register("invalid_adapter")  # type: ignore[arg-type]

    # Unregister
    assert registry.unregister("custom_linter") is True
    assert registry.get("custom_linter") is None
    assert registry.unregister("custom_linter") is False


