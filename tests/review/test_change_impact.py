"""Unit tests for LogicFalcon Change Impact Analysis and Predictive Test Selection."""

from pathlib import Path

import pytest

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.impact.change_detector import ChangeSetDetector
from packages.review.impact.engine import ChangeImpactEngine
from packages.review.impact.models import (
    ConfidenceCategory,
    ImpactRiskLevel,
    ImpactType,
)
from packages.review.impact.propagator import ImpactPropagator
from packages.review.impact.report_generator import ChangeImpactReportGenerator
from packages.review.impact.scorer import ImpactScorer
from packages.review.impact.test_selector import PredictiveTestSelector


@pytest.fixture
def sample_impact_repo(tmp_path: Path) -> Path:
    """Creates a sample multi-layer repository with dependencies and tests."""
    repo = tmp_path / "impact_repo"
    repo.mkdir()

    # Core domain model
    domain_dir = repo / "domain"
    domain_dir.mkdir()
    (domain_dir / "__init__.py").write_text("")
    (domain_dir / "user.py").write_text(
        """class User:
    def __init__(self, name: str):
        self.name = name
"""
    )

    # Service layer importing domain
    services_dir = repo / "services"
    services_dir.mkdir()
    (services_dir / "__init__.py").write_text("")
    (services_dir / "user_service.py").write_text(
        """from domain.user import User

class UserService:
    def get_user(self, name: str) -> User:
        return User(name)
"""
    )

    # API presentation layer importing service
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "__init__.py").write_text("")
    (api_dir / "routes.py").write_text(
        """from services.user_service import UserService

service = UserService()

def get_user_route(name: str):
    return service.get_user(name)
"""
    )

    # Direct unit test importing domain/user.py
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_user.py").write_text(
        """from domain.user import User

def test_user_creation():
    u = User('Alice')
    assert u.name == 'Alice'
"""
    )

    # Integration test importing api/routes.py
    (tests_dir / "test_api.py").write_text(
        """from api.routes import get_user_route

def test_get_user_route():
    assert get_user_route('Bob').name == 'Bob'
"""
    )

    # Isolated module without dependents
    (repo / "isolated.py").write_text("x = 42\n")

    return repo


def test_change_set_detector_explicit_files(sample_impact_repo: Path) -> None:
    """Verifies that ChangeSetDetector correctly builds change sets from explicit file lists."""
    detector = ChangeSetDetector(repo_root=sample_impact_repo)
    cs = detector.from_explicit_files(["domain/user.py", "nonexistent/file.py"])

    assert len(cs.changed_files) == 1
    assert cs.changed_files[0].new_path == "domain/user.py"
    assert "domain/user.py" in cs.modified_paths
    assert "nonexistent/file.py" in cs.unresolved_paths
    assert cs.origin == "explicit_files"


def test_change_set_detector_from_unified_diff(sample_impact_repo: Path) -> None:
    """Verifies parsing of git diff with additions, modifications, renames, and deletions."""
    raw_diff = """diff --git a/domain/user.py b/domain/user.py
index 1234567..89abcdef 100644
--- a/domain/user.py
+++ b/domain/user.py
@@ -1,3 +1,4 @@
 class User:
+    age: int = 0
     def __init__(self, name: str):
         self.name = name
diff --git a/old_config.py b/new_config.py
similarity index 95%
rename from old_config.py
rename to new_config.py
diff --git a/obsolete.py b/obsolete.py
deleted file mode 100644
--- a/obsolete.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def dead():
-    pass
"""
    detector = ChangeSetDetector(repo_root=sample_impact_repo)
    cs = detector._build_change_set_from_diff(
        raw_diff=raw_diff,
        origin="git_diff",
        base_rev="HEAD~1",
        target_rev="HEAD",
    )

    assert "domain/user.py" in cs.modified_paths
    assert "new_config.py" in cs.modified_paths
    assert ("old_config.py", "new_config.py") in cs.renamed_paths
    assert "obsolete.py" in cs.deleted_paths
    assert cs.total_added_lines >= 1


def test_direct_and_transitive_propagation(sample_impact_repo: Path) -> None:
    """Verifies propagation from domain/user.py to direct (user_service) and transitive (api/routes) dependents."""
    graph = DependencyGraph(sample_impact_repo)
    graph.build_graph()

    propagator = ImpactPropagator(repo_root=sample_impact_repo, dependency_graph=graph, max_depth=5)
    detector = ChangeSetDetector(repo_root=sample_impact_repo)
    cs = detector.from_explicit_files(["domain/user.py"])

    entities, limitations = propagator.propagate(cs)
    assert len(limitations) == 0

    paths = {e.file_path: e for e in entities}
    assert "services/user_service.py" in paths
    assert paths["services/user_service.py"].depth == 1
    assert paths["services/user_service.py"].impact_type == ImpactType.DIRECT_DEPENDENCY

    assert "api/routes.py" in paths
    assert paths["api/routes.py"].depth == 2
    assert paths["api/routes.py"].impact_type == ImpactType.TRANSITIVE_DEPENDENCY
    assert paths["api/routes.py"].shortest_path == ["domain/user.py", "services/user_service.py", "api/routes.py"]


def test_dependency_cycle_infinite_loop_defense(tmp_path: Path) -> None:
    """Verifies that circular dependency cycles terminate without infinite recursion."""
    repo = tmp_path / "cycle_repo"
    repo.mkdir()

    (repo / "__init__.py").write_text("")
    (repo / "mod_a.py").write_text("import mod_b\na_val = 1\n")
    (repo / "mod_b.py").write_text("import mod_a\nb_val = 2\n")

    graph = DependencyGraph(repo)
    graph.build_graph()

    detector = ChangeSetDetector(repo)
    cs = detector.from_explicit_files(["mod_a.py"])

    propagator = ImpactPropagator(repo, dependency_graph=graph, max_depth=5)
    entities, _ = propagator.propagate(cs)

    # Must only visit mod_b once and terminate safely
    assert len(entities) == 1
    assert entities[0].file_path == "mod_b.py"


def test_explainable_scoring_and_factors(sample_impact_repo: Path) -> None:
    """Verifies that ImpactScorer assigns deterministic scores with transparent rationales."""
    graph = DependencyGraph(sample_impact_repo)
    graph.build_graph()

    detector = ChangeSetDetector(sample_impact_repo)
    cs = detector.from_explicit_files(["domain/user.py"])

    propagator = ImpactPropagator(sample_impact_repo, dependency_graph=graph)
    entities, _ = propagator.propagate(cs)

    scorer = ImpactScorer()
    scorer.score_entities(entities)

    for ent in entities:
        assert ent.impact_score > 0.0
        assert len(ent.impact_reasons) > 0
        if ent.depth == 1:
            assert ent.impact_score >= 30.0

    risk_level, score, reasons = scorer.evaluate_change_risk(cs, entities)
    assert score > 0.0
    assert risk_level in (ImpactRiskLevel.LOW, ImpactRiskLevel.MEDIUM)
    assert len(reasons) > 0


def test_critical_risk_classification_on_migration_and_security(tmp_path: Path) -> None:
    """Verifies that modifying migrations and security components elevates risk to CRITICAL."""
    repo = tmp_path / "crit_repo"
    repo.mkdir()

    (repo / "auth_security.py").write_text("TOKEN = 'secret'\n")
    (repo / "0002_migration.py").write_text("def upgrade(): pass\n")

    detector = ChangeSetDetector(repo)
    cs = detector.from_explicit_files(["auth_security.py", "0002_migration.py"])

    scorer = ImpactScorer()
    risk_level, score, reasons = scorer.evaluate_change_risk(cs, [])

    assert risk_level == ImpactRiskLevel.CRITICAL
    assert score >= 75.0
    assert any("migration" in r.lower() for r in reasons)
    assert any("security" in r.lower() for r in reasons)


def test_predictive_test_selection(sample_impact_repo: Path) -> None:
    """Verifies that PredictiveTestSelector identifies direct, transitive, and convention tests."""
    graph = DependencyGraph(sample_impact_repo)
    graph.build_graph()

    detector = ChangeSetDetector(sample_impact_repo)
    cs = detector.from_explicit_files(["domain/user.py"])

    propagator = ImpactPropagator(sample_impact_repo, dependency_graph=graph)
    entities, _ = propagator.propagate(cs)

    selector = PredictiveTestSelector(sample_impact_repo, dependency_graph=graph)
    recommended = selector.select_tests(cs, entities)

    test_files = [t.test_file for t in recommended]
    assert "tests/test_user.py" in test_files
    assert "tests/test_api.py" in test_files

    # test_user.py imports domain/user.py directly -> HIGH confidence
    user_test = next(t for t in recommended if t.test_file == "tests/test_user.py")
    assert user_test.confidence == ConfidenceCategory.HIGH
    assert user_test.relationship_type == ImpactType.DIRECT_DEPENDENCY

    # test_api.py imports api/routes.py (transitive) -> MEDIUM confidence
    api_test = next(t for t in recommended if t.test_file == "tests/test_api.py")
    assert api_test.confidence == ConfidenceCategory.MEDIUM
    assert api_test.relationship_type == ImpactType.TRANSITIVE_DEPENDENCY


def test_conservative_test_selection_mode(sample_impact_repo: Path) -> None:
    """Verifies conservative fallback mode selects all repository tests."""
    graph = DependencyGraph(sample_impact_repo)
    graph.build_graph()

    detector = ChangeSetDetector(sample_impact_repo)
    # isolated.py has no dependents or tests importing it
    cs = detector.from_explicit_files(["isolated.py"])

    selector = PredictiveTestSelector(sample_impact_repo, dependency_graph=graph, conservative_mode=True)
    recommended = selector.select_tests(cs, [])

    test_files = [t.test_file for t in recommended]
    assert "tests/test_user.py" in test_files
    assert "tests/test_api.py" in test_files
    assert any("conservative mode" in t.selection_reason.lower() for t in recommended)


def test_change_impact_report_serialization_and_redaction(sample_impact_repo: Path) -> None:
    """Verifies report generation across JSON, text, and Markdown formats with Mermaid diagram generation."""
    engine = ChangeImpactEngine(sample_impact_repo)
    report = engine.analyze(explicit_files=["domain/user.py"])

    generator = ChangeImpactReportGenerator(report)
    json_out = generator.to_json()
    assert '"risk_level"' in json_out
    assert '"impacted_entities"' in json_out

    text_out = generator.to_text()
    assert "Change Impact Intelligence" in text_out
    assert "Recommended Tests to Run" in text_out

    md_out = generator.to_markdown()
    assert "# LogicFalcon — Change Impact Intelligence Report" in md_out
    assert "```mermaid" in md_out
    assert "flowchart TD" in md_out
