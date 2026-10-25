"""Adversarial and security tests for LogicFalcon Change Impact Intelligence."""

from pathlib import Path

import pytest

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.impact.change_detector import ChangeSetDetector
from packages.review.impact.engine import ChangeImpactEngine
from packages.review.impact.models import ChangeSet
from packages.review.impact.propagator import ImpactPropagator
from packages.review.impact.report_generator import ChangeImpactReportGenerator


def test_path_traversal_via_explicit_files_rejected(tmp_path: Path) -> None:
    """Verifies that attempts to pass paths outside repository boundary are rejected."""
    repo = tmp_path / "safe_repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")

    detector = ChangeSetDetector(repo_root=repo)
    cs = detector.from_explicit_files(["../../etc/passwd", "../sibling/secret.py", "app.py"])

    # Path traversal attempts must be in unresolved_paths and NOT in changed_files
    assert "../../etc/passwd" in cs.unresolved_paths
    assert "../sibling/secret.py" in cs.unresolved_paths
    assert len(cs.changed_files) == 1
    assert cs.changed_files[0].new_path == "app.py"


def test_shell_injection_attempt_in_revision_rejected(tmp_path: Path) -> None:
    """Verifies that malicious shell injection payloads in revision arguments are rejected."""
    repo = tmp_path / "rev_repo"
    repo.mkdir()

    detector = ChangeSetDetector(repo_root=repo)
    malicious_revs = [
        "main; rm -rf /",
        "HEAD && touch pwned",
        "`cat /etc/passwd`",
        "$(whoami)",
        "HEAD|reboot",
    ]

    for mal_rev in malicious_revs:
        with pytest.raises(ValueError, match="Invalid characters in"):
            detector.from_revisions(base_rev=mal_rev, target_rev="HEAD")


def test_output_path_directory_traversal_escape_rejected(tmp_path: Path) -> None:
    """Verifies that report writer rejects paths escaping repository root."""
    repo = tmp_path / "escape_repo"
    repo.mkdir()

    engine = ChangeImpactEngine(repo)
    report = engine.analyze(change_set=ChangeSet())
    generator = ChangeImpactReportGenerator(report)

    with pytest.raises(PermissionError, match="Rejected report path outside repository"):
        generator.write_to_file("../../escaped_report.md", repo_root=repo)


def test_source_code_overwrite_defense(tmp_path: Path) -> None:
    """Verifies that report writer refuses to overwrite source code files (.py, .ts, etc.)."""
    repo = tmp_path / "overwrite_repo"
    repo.mkdir()
    source_file = repo / "main.py"
    source_file.write_text("print('critical source code')\n")

    engine = ChangeImpactEngine(repo)
    report = engine.analyze(change_set=ChangeSet())
    generator = ChangeImpactReportGenerator(report)

    with pytest.raises(PermissionError, match="Refusing to write report to source code file"):
        generator.write_to_file(str(source_file), repo_root=repo)

    # Source content must remain unchanged
    assert "critical source code" in source_file.read_text()


def test_secret_redaction_across_impact_reports(tmp_path: Path) -> None:
    """CRITICAL SECURITY TEST: Verifies that synthetic secret tokens and URIs are redacted in reports."""
    repo = tmp_path / "secret_repo"
    repo.mkdir()

    # Injected synthetic secrets in path and symbols
    fake_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    fake_uri = "postgres://admin:super_secret_pw@db.internal:5432/corp"

    (repo / "secret_service.py").write_text(
        f"""# Sensitive configuration
API_KEY = "{fake_token}"
DATABASE_URL = "{fake_uri}"
"""
    )

    engine = ChangeImpactEngine(repo)
    report = engine.analyze(explicit_files=["secret_service.py"])
    # Ingest synthetic secret evidence snippet into risk reasons
    report.risk_reasons.append(f"Connection string: {fake_uri}")
    report.risk_reasons.append(f"Auth header: Bearer {fake_token}")

    generator = ChangeImpactReportGenerator(report)

    md = generator.to_markdown()
    assert fake_token not in md
    assert "super_secret_pw" not in md
    assert "[REDACTED_PASSWORD]" in md
    assert "[REDACTED_TOKEN]" in md or "REDACTED" in md

    txt = generator.to_text()
    assert fake_token not in txt
    assert "super_secret_pw" not in txt


def test_oversized_entity_limit_defense(tmp_path: Path) -> None:
    """Verifies that max_entities bounds traversal and records a structured limitation."""
    repo = tmp_path / "limit_repo"
    repo.mkdir()

    (repo / "__init__.py").write_text("")
    (repo / "core.py").write_text("x = 1\n")
    for i in range(10):
        (repo / f"dep_{i}.py").write_text(f"import core\ny_{i} = {i}\n")

    graph = DependencyGraph(repo)
    graph.build_graph()

    detector = ChangeSetDetector(repo)
    cs = detector.from_explicit_files(["core.py"])

    # Limit to 3 entities
    propagator = ImpactPropagator(repo, dependency_graph=graph, max_entities=3)
    entities, limitations = propagator.propagate(cs)

    assert len(entities) == 3
    assert any(lim.category == "entity_limit_exceeded" for lim in limitations)


def test_deep_recursion_max_depth_bound(tmp_path: Path) -> None:
    """Verifies that max_depth limits transitive propagation depth."""
    repo = tmp_path / "depth_repo"
    repo.mkdir()

    # Chain: m5 -> m4 -> m3 -> m2 -> m1 -> m0
    (repo / "__init__.py").write_text("")
    (repo / "m0.py").write_text("val = 0\n")
    for i in range(1, 6):
        (repo / f"m{i}.py").write_text(f"import m{i-1}\nval = {i}\n")

    graph = DependencyGraph(repo)
    graph.build_graph()

    detector = ChangeSetDetector(repo)
    cs = detector.from_explicit_files(["m0.py"])

    # Limit to depth 2
    propagator = ImpactPropagator(repo, dependency_graph=graph, max_depth=2)
    entities, _ = propagator.propagate(cs)

    depths = [e.depth for e in entities]
    assert max(depths) <= 2
    assert "m1.py" in [e.file_path for e in entities]
    assert "m2.py" in [e.file_path for e in entities]
    assert "m3.py" not in [e.file_path for e in entities]


def test_empty_change_set_handled_gracefully(tmp_path: Path) -> None:
    """Verifies that an empty change set completes with 0 score and zero crashes."""
    repo = tmp_path / "empty_repo"
    repo.mkdir()
    (repo / "clean.py").write_text("x = 1\n")

    engine = ChangeImpactEngine(repo)
    report = engine.analyze(explicit_files=[])

    assert report.risk_score == 0.0
    assert len(report.impacted_entities) == 0
    assert len(report.recommended_tests) == 0
