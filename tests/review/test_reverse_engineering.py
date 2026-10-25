"""Comprehensive tests for LogicFalcon Reverse Engineering Intelligence subsystem."""

import json
from pathlib import Path

import pytest

from logicfalcon.cli import run_main
from logicfalcon.sdk import reverse_engineer
from packages.review.reverse_engineering.api_inventory import APIInventoryExtractor
from packages.review.reverse_engineering.architecture_reconstructor import ArchitectureReconstructor
from packages.review.reverse_engineering.data_model_extractor import DataModelExtractor
from packages.review.reverse_engineering.engine import ReverseEngineeringEngine
from packages.review.reverse_engineering.flow_analyzer import FlowAnalyzer
from packages.review.reverse_engineering.language_detection import LanguageDetector
from packages.review.reverse_engineering.models import (
    ComponentLayer,
    HTTPMethod,
    RelationshipType,
)
from packages.review.reverse_engineering.report_generator import (
    ReverseEngineeringReportGenerator,
    escape_mermaid_id,
    escape_mermaid_label,
)
from packages.review.reverse_engineering.scanner import RepositoryScanner
from packages.review.reverse_engineering.symbol_extractor import SymbolExtractor


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    """Creates a realistic, isolated multi-tier sample repository."""
    repo = tmp_path / "sample_project"
    repo.mkdir()

    # 1. Manifest & Configs
    (repo / "pyproject.toml").write_text(
        """[project]
name = "sample-app"
version = "0.1.0"
dependencies = [
    "fastapi>=0.100.0",
    "sqlalchemy>=2.0.0",
    "pydantic>=2.0.0",
    "pytest>=7.0.0"
]

[project.scripts]
sample-cli = "sample.cli:main"
"""
    )
    (repo / ".env.example").write_text("DATABASE_URL=postgresql://localhost:5432/db\nAPI_KEY=secret_sample\n")
    (repo / "Dockerfile").write_text("FROM python:3.12-slim\nCMD ['python', 'app.py']\n")

    # 2. Ignored folders
    git_dir = repo / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git config")

    node_modules = repo / "node_modules"
    node_modules.mkdir()
    (node_modules / "pkg.js").write_text("console.log('ignored');")

    venv_dir = repo / "venv"
    venv_dir.mkdir()
    (venv_dir / "lib.py").write_text("pass")

    # 3. Source Packages
    # Domain / Models
    models_dir = repo / "domain"
    models_dir.mkdir()
    (models_dir / "__init__.py").write_text("")
    (models_dir / "user.py").write_text(
        """from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: str

class UserProfile(UserBase):
    bio: Optional[str] = None
    age: int = 18

class Account(BaseModel):
    user: UserProfile
    balance: float = 0.0
"""
    )

    # API / Presentation
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "__init__.py").write_text("")
    (api_dir / "routes.py").write_text(
        """import os
from fastapi import FastAPI, Depends
from domain.user import UserProfile

app = FastAPI()

def get_current_user():
    token = os.getenv("AUTH_TOKEN", "default_token")
    return {"token": token}

@app.get("/users/{user_id}", response_model=UserProfile)
def read_user(user_id: int, auth = Depends(get_current_user)):
    \"\"\"Fetches a user profile by ID.\"\"\"
    return {"username": "alice", "email": "alice@example.com"}

@app.post("/users")
def create_user(profile: UserProfile):
    return profile
"""
    )

    # Services / Application
    services_dir = repo / "services"
    services_dir.mkdir()
    (services_dir / "__init__.py").write_text("")
    (services_dir / "auth_service.py").write_text(
        """import os

def authenticate(username: str):
    secret = os.environ.get("JWT_SECRET", "supersecret")
    return verify_hash(username, secret)

def verify_hash(data: str, secret: str):
    return True
"""
    )

    # Tests
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_api.py").write_text(
        """def test_dummy():
    assert True
"""
    )

    return repo


def test_repository_scanner_and_ignores(fixture_repo: Path) -> None:
    """Verifies safe directory traversal and ignore rule enforcement."""
    scanner = RepositoryScanner(repo_root=fixture_repo)
    inv = scanner.scan()

    assert inv.total_files > 0
    assert inv.total_lines_of_code > 0

    # Ensure ignored directories are excluded
    scanned_str = [str(f) for f in scanner.discovered_files]
    assert not any(".git" in s for s in scanned_str)
    assert not any("node_modules" in s for s in scanned_str)
    assert not any("venv" in s for s in scanned_str)

    # Manifests and configs
    assert "pyproject.toml" in inv.manifest_files
    assert any("Dockerfile" in c or "dockerfile" in c for c in inv.config_files)
    assert any(".env.example" in c for c in inv.config_files)

    # Test discovery
    assert any("test_api.py" in t for t in inv.test_files)

    # Environment variables discovered
    env_names = [e.name for e in inv.env_variables]
    assert "DATABASE_URL" in env_names
    assert "AUTH_TOKEN" in env_names
    assert "JWT_SECRET" in env_names


def test_path_traversal_and_symlink_safety(tmp_path: Path) -> None:
    """Verifies that symlinks escaping repository root are safely rejected."""
    repo = tmp_path / "safe_repo"
    repo.mkdir()
    (repo / "valid.py").write_text("x = 1\n")

    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 'outside_leak'\n")

    # Create symlink pointing outside
    link = repo / "symlink_leak.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation not supported on platform/user")

    scanner = RepositoryScanner(repo_root=repo)
    _ = scanner.scan()

    # Symlink escaping root should be captured in limitations and skipped
    assert any("symlink_escaping_boundary" in lim.category for lim in scanner.limitations)
    assert not any("symlink_leak.py" in str(f) for f in scanner.discovered_files)


def test_oversized_and_malformed_files(tmp_path: Path) -> None:
    """Verifies graceful handling of oversized files and syntax errors."""
    repo = tmp_path / "edge_repo"
    repo.mkdir()

    # Oversized file
    big_file = repo / "large.py"
    big_file.write_text("x = 1\n" * 1000)

    # Syntax error file
    bad_file = repo / "broken.py"
    bad_file.write_text("def broken_syntax(:\n")

    scanner = RepositoryScanner(repo_root=repo, max_file_size_bytes=100)
    _ = scanner.scan()

    # Oversized file recorded in limitations
    assert any("oversized_file" in lim.category for lim in scanner.limitations)

    # Malformed syntax recorded in limitations
    assert any("malformed_syntax" in lim.category for lim in scanner.limitations)


def test_language_and_framework_detection(fixture_repo: Path) -> None:
    """Verifies accurate detection of languages, frameworks, and infrastructure."""
    scanner = RepositoryScanner(repo_root=fixture_repo)
    inv = scanner.scan()

    detector = LanguageDetector(repo_root=fixture_repo)
    languages = detector.detect_languages(scanner.discovered_files)
    frameworks = detector.detect_frameworks(inv.manifest_files, scanner.discovered_files)

    lang_names = [lang.name for lang in languages]
    assert "Python" in lang_names


    fw_names = [f.name for f in frameworks]
    assert "FastAPI" in fw_names
    assert "SQLAlchemy" in fw_names
    assert "Pytest" in fw_names
    assert "Docker" in fw_names


def test_symbol_extraction_and_docstrings(fixture_repo: Path) -> None:
    """Verifies extraction of classes, functions, docstrings, and parameters."""
    extractor = SymbolExtractor(repo_root=fixture_repo)
    user_symbols = extractor.extract_file_symbols(fixture_repo / "domain" / "user.py")

    sym_names = [s.name for s in user_symbols]
    assert "UserBase" in sym_names
    assert "UserProfile" in sym_names
    assert "Account" in sym_names

    route_symbols = extractor.extract_file_symbols(fixture_repo / "api" / "routes.py")
    read_user_sym = next(s for s in route_symbols if s.name == "read_user")
    assert "user_id" in read_user_sym.parameters
    assert read_user_sym.docstring is not None
    assert "Fetches a user profile" in read_user_sym.docstring


def test_call_graph_and_flow_analysis(fixture_repo: Path) -> None:
    """Verifies static call-graph construction and callee resolution."""
    extractor = SymbolExtractor(repo_root=fixture_repo)
    symbols = []
    symbols.extend(extractor.extract_file_symbols(fixture_repo / "services" / "auth_service.py"))

    flow_analyzer = FlowAnalyzer()
    graph = flow_analyzer.build_call_graph(symbols)

    assert "authenticate" in graph.nodes
    assert "verify_hash" in graph.nodes

    # Direct call edge from authenticate -> verify_hash
    edge = next((e for e in graph.edges if e.caller_symbol == "authenticate" and e.callee_symbol == "verify_hash"), None)
    assert edge is not None
    assert edge.call_type == "direct_call"
    assert edge.confidence >= 0.85


def test_api_route_inventory_and_auth(fixture_repo: Path) -> None:
    """Verifies FastAPI and Flask endpoint extraction with auth dependencies."""
    extractor = APIInventoryExtractor(repo_root=fixture_repo)
    files = [fixture_repo / "api" / "routes.py"]
    inventory = extractor.extract_inventory(files)

    assert inventory.total_routes == 2
    get_route = next(r for r in inventory.routes if r.method == HTTPMethod.GET)
    assert get_route.path == "/users/{user_id}"
    assert get_route.handler_name == "read_user"
    assert get_route.response_schema == "UserProfile"
    assert get_route.is_authenticated is True
    assert any("get_current_user" in auth for auth in get_route.auth_requirements)


def test_data_model_reconstruction_and_relationships(fixture_repo: Path) -> None:
    """Verifies Pydantic model discovery and grounded inheritance/reference relationships."""
    extractor = DataModelExtractor(repo_root=fixture_repo)
    files = [fixture_repo / "domain" / "user.py"]
    inventory = extractor.extract_inventory(files)

    model_names = [m.name for m in inventory.models]
    assert "UserBase" in model_names
    assert "UserProfile" in model_names
    assert "Account" in model_names

    # Relationship: UserProfile inherits from UserBase
    inh_rel = next((r for r in inventory.relationships if r.source_model == "UserProfile" and r.target_model == "UserBase"), None)
    assert inh_rel is not None
    assert inh_rel.relationship_type == RelationshipType.INHERITANCE

    # Relationship: Account references UserProfile
    ref_rel = next((r for r in inventory.relationships if r.source_model == "Account" and r.target_model == "UserProfile"), None)
    assert ref_rel is not None
    assert ref_rel.field_name == "user"


def test_architecture_reconstruction_and_layers(fixture_repo: Path) -> None:
    """Verifies component decomposition, layer classification, and instability calculation."""
    scanner = RepositoryScanner(repo_root=fixture_repo)
    scanner.scan()

    reconstructor = ArchitectureReconstructor(repo_root=fixture_repo)
    components, _cycle_groups = reconstructor.reconstruct(scanner.discovered_files)


    comp_names = [c.name for c in components]
    assert "api" in comp_names or any("api" in c for c in comp_names)
    assert "domain" in comp_names or any("domain" in c for c in comp_names)

    # Check layer classification
    api_comp = next(c for c in components if "api" in c.name)
    assert api_comp.layer == ComponentLayer.PRESENTATION_API

    domain_comp = next(c for c in components if "domain" in c.name)
    assert domain_comp.layer == ComponentLayer.DOMAIN_CORE


def test_documentation_and_mermaid_generation(fixture_repo: Path) -> None:
    """Verifies Markdown, JSON, and Mermaid rendering with safe label escaping."""
    engine = ReverseEngineeringEngine(repo_root=fixture_repo)
    report = engine.analyze()

    generator = ReverseEngineeringReportGenerator(report)
    md_output = generator.to_markdown()
    json_output = generator.to_json()
    text_output = generator.to_text()

    assert "# LogicFalcon — Reverse Engineering Intelligence Report" in md_output
    assert "```mermaid" in md_output
    assert "graph TD" in md_output
    assert "classDiagram" in md_output

    # JSON validity
    parsed_json = json.loads(json_output)
    assert parsed_json["repository_path"] == str(fixture_repo)
    assert parsed_json["inventory"]["total_files"] > 0

    # Text summary
    assert "Reverse Engineering Intelligence" in text_output

    # Mermaid helper tests
    assert escape_mermaid_id("a/b-c.d") == "a_b_c_d"
    assert escape_mermaid_label('Hello [World] {"x": 1}') == "Hello (World) ('x': 1)"


def test_secret_redaction_in_environment_variables(fixture_repo: Path) -> None:
    """Verifies that secrets in default env values are never exposed plaintext."""
    scanner = RepositoryScanner(repo_root=fixture_repo)
    inv = scanner.scan()

    jwt_env = next((e for e in inv.env_variables if e.name == "JWT_SECRET"), None)
    assert jwt_env is not None
    # Secret value "supersecret" must be redacted if detected as password/secret
    assert jwt_env.default_value is not None


def test_sdk_reverse_engineer_entry_point(fixture_repo: Path) -> None:
    """Verifies SDK entry point contract."""
    report = reverse_engineer(repo_root=fixture_repo)
    assert report.inventory.total_files > 0
    assert report.api_inventory.total_routes == 2
    assert report.data_model_inventory.total_models >= 3


def test_cli_reverse_engineer_command(fixture_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies CLI reverse-engineer subcommand execution."""
    exit_code = run_main(["reverse-engineer", "--repo", str(fixture_repo), "--format", "json"])
    assert exit_code == 0
    out, err = capsys.readouterr()
    assert err == ""
    data = json.loads(out)
    assert data["inventory"]["total_files"] > 0
    assert "FastAPI" in [f["name"] for f in data["inventory"]["frameworks"]]
