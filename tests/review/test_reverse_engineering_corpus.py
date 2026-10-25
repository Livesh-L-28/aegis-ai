"""Evidence-driven test corpus for LogicFalcon Reverse Engineering Intelligence.

Validates semantic accuracy on realistic polyglot fixtures:
- Python multi-tier application (FastAPI, Flask, SQLAlchemy, Pydantic, circular imports, syntax errors).
- TypeScript / JavaScript application (Express routes, interfaces, package.json bin).
- Infrastructure & environment configuration (Dockerfile, .env.example).
"""

from pathlib import Path

import pytest

from packages.review.reverse_engineering.engine import ReverseEngineeringEngine
from packages.review.reverse_engineering.models import RelationshipType


@pytest.fixture
def polyglot_corpus_repo(tmp_path: Path) -> Path:
    """Builds a rich deterministic multi-language fixture repository."""
    repo = tmp_path / "polyglot_corpus"
    repo.mkdir()

    # 1. Manifests & Config
    (repo / "pyproject.toml").write_text(
        """[project]
name = "corpus-app"
version = "1.0.0"
dependencies = ["fastapi", "flask", "sqlalchemy", "pydantic"]

[project.scripts]
corpus-cli = "corpus.cli:main"
"""
    )
    (repo / "package.json").write_text(
        """{
  "name": "corpus-web",
  "version": "1.0.0",
  "bin": {
    "corpus-node": "./bin/index.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}"""
    )
    (repo / "Dockerfile").write_text("FROM python:3.12-slim\nEXPOSE 8080\n")
    (repo / ".env.example").write_text("DATABASE_URL=postgresql://localhost:5432/app\nPORT=8080\n")

    # 2. Python Tier: Domain Models
    domain_dir = repo / "domain"
    domain_dir.mkdir()
    (domain_dir / "__init__.py").write_text("")
    (domain_dir / "models.py").write_text(
        """from pydantic import BaseModel
from typing import Optional, TypedDict

class EntityBase(BaseModel):
    id: int
    created_at: str

class UserEntity(EntityBase):
    username: str
    email: str
    is_active: bool = True

class SessionState(TypedDict):
    session_id: str
    authenticated: bool
"""
    )

    # 3. Python Tier: Database (SQLAlchemy)
    db_dir = repo / "db"
    db_dir.mkdir()
    (db_dir / "__init__.py").write_text("")
    (db_dir / "schema.py").write_text(
        """from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    items = relationship("DBItem", back_populates="owner")

class DBItem(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
"""
    )

    # 4. Python Tier: API Routes (FastAPI & Flask)
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "__init__.py").write_text("")
    (api_dir / "fastapi_routes.py").write_text(
        """from fastapi import FastAPI, Depends, Security
from domain.models import UserEntity

app = FastAPI()

def get_current_user():
    return {"user": "admin"}

@app.get("/api/v1/users/{user_id}", response_model=UserEntity)
def get_user_endpoint(user_id: int, user = Depends(get_current_user)):
    return {"id": user_id, "username": "admin", "email": "a@a.com", "created_at": "now"}

@app.post("/api/v1/users")
def create_user_endpoint(entity: UserEntity):
    return entity
"""
    )
    (api_dir / "flask_routes.py").write_text(
        """from flask import Flask

flask_app = Flask(__name__)

def login_required(fn):
    return fn

@flask_app.route("/health", methods=["GET"])
def health_check():
    return {"status": "ok"}

@flask_app.route("/secure/data", methods=["POST"])
@login_required
def secure_data():
    return {"data": 42}
"""
    )

    # 5. Python Tier: Circular Dependencies (circular_a <-> circular_b)
    services_dir = repo / "services"
    services_dir.mkdir()
    (services_dir / "__init__.py").write_text("")
    (services_dir / "circular_a.py").write_text(
        """from services.circular_b import service_b_action

def service_a_action():
    return service_b_action()
"""
    )
    (services_dir / "circular_b.py").write_text(
        """from services.circular_a import service_a_action

def service_b_action():
    return True
"""
    )

    # 6. Degraded / Partially parseable file
    (services_dir / "broken_syntax.py").write_text(
        """def valid_func():
    return 1

def broken_func(
    # Missing closing parenthesis and colon
"""
    )

    # 7. Dynamic imports / Reflection
    (services_dir / "dynamic_loader.py").write_text(
        """import importlib

def load_plugin(name: str):
    return importlib.import_module(name)
"""
    )

    # 8. TypeScript / JavaScript Tier
    js_dir = repo / "src"
    js_dir.mkdir()
    (js_dir / "server.ts").write_text(
        """import express from 'express';

const app = express();

function requireAuth(req: any, res: any, next: any) {
    next();
}

app.get('/api/items', (req, res) => {
    res.json([]);
});

app.post('/api/items', requireAuth, (req, res) => {
    res.status(201).json({});
});
"""
    )
    (js_dir / "models.ts").write_text(
        """export interface ItemModel {
    id: string;
    title: string;
}

export class OrderService {
    calculateTotal(items: ItemModel[]): number {
        return items.length * 10;
    }
}
"""
    )

    return repo


def test_corpus_multi_tier_languages_and_manifests(polyglot_corpus_repo: Path) -> None:
    """Verifies polyglot language identification and manifest entry points."""
    engine = ReverseEngineeringEngine(repo_root=polyglot_corpus_repo)
    report = engine.analyze()

    lang_names = {lang.name for lang in report.inventory.languages}
    assert "Python" in lang_names
    assert "TypeScript" in lang_names

    fw_names = {fw.name for fw in report.inventory.frameworks}
    assert "FastAPI" in fw_names
    assert "Flask" in fw_names
    assert "SQLAlchemy" in fw_names
    assert "Pydantic" in fw_names

    ep_names = {ep.name for ep in report.inventory.entry_points}
    assert "corpus-cli" in ep_names
    assert "corpus-node" in ep_names


def test_corpus_api_inventory_semantic_accuracy(polyglot_corpus_repo: Path) -> None:
    """Verifies exact HTTP methods, endpoints, schemas, and auth classification."""
    engine = ReverseEngineeringEngine(repo_root=polyglot_corpus_repo)
    report = engine.analyze()

    routes = {f"{r.method.value} {r.path}": r for r in report.api_inventory.routes}

    # 1. FastAPI GET with Depends(get_current_user)
    get_user = routes.get("GET /api/v1/users/{user_id}")
    assert get_user is not None
    assert get_user.framework == "FastAPI"
    assert get_user.handler_name == "get_user_endpoint"
    assert get_user.auth_detected is True
    assert any("get_current_user" in a for a in get_user.auth_requirements)

    # 2. FastAPI POST without explicit auth
    post_user = routes.get("POST /api/v1/users")
    assert post_user is not None
    assert post_user.auth_detected is False

    # 3. Flask GET unauthenticated
    flask_health = routes.get("GET /health")
    assert flask_health is not None
    assert flask_health.framework == "Flask"
    assert flask_health.auth_detected is False

    # 4. Flask POST with @login_required
    flask_secure = routes.get("POST /secure/data")
    assert flask_secure is not None
    assert flask_secure.auth_detected is True
    assert any("login_required" in a for a in flask_secure.auth_requirements)

    # 5. Express GET and POST with requireAuth
    express_get = routes.get("GET /api/items")
    assert express_get is not None
    assert express_get.framework == "Express"

    express_post = routes.get("POST /api/items")
    assert express_post is not None
    assert express_post.auth_detected is True


def test_corpus_data_model_relationships(polyglot_corpus_repo: Path) -> None:
    """Verifies model types (Pydantic, SQLAlchemy, TypedDict) and grounded relationships."""
    engine = ReverseEngineeringEngine(repo_root=polyglot_corpus_repo)
    report = engine.analyze()

    models = {m.name: m for m in report.data_model_inventory.models}
    assert "UserEntity" in models
    assert models["UserEntity"].model_type == "pydantic"

    assert "DBUser" in models
    assert models["DBUser"].model_type == "sqlalchemy"

    assert "SessionState" in models
    assert models["SessionState"].model_type == "typeddict"

    # Inheritance relationship: UserEntity inherits EntityBase
    inheritance_rels = [
        r for r in report.data_model_inventory.relationships
        if r.relationship_type == RelationshipType.INHERITANCE
    ]
    assert any(
        r.source_model == "UserEntity" and r.target_model == "EntityBase"
        for r in inheritance_rels
    )


def test_corpus_circular_import_detection(polyglot_corpus_repo: Path) -> None:
    """Verifies that circular dependency groups (SCCs) are identified."""
    engine = ReverseEngineeringEngine(repo_root=polyglot_corpus_repo)
    report = engine.analyze()

    # Verify cycle groups found
    assert len(report.cycle_groups) > 0
    cycle_modules = [m for cg in report.cycle_groups for m in cg.get("modules", [])]
    assert any("circular_a" in m for m in cycle_modules)
    assert any("circular_b" in m for m in cycle_modules)


def test_corpus_graceful_degradation_on_syntax_error(polyglot_corpus_repo: Path) -> None:
    """Verifies that broken source files produce structured limitations without aborting scan."""
    engine = ReverseEngineeringEngine(repo_root=polyglot_corpus_repo)
    report = engine.analyze()

    # The scan should succeed and catalog other files
    assert report.inventory.total_files > 5

    # Should report syntax error limitation for broken_syntax.py
    syntax_lims = [
        lim for lim in report.limitations
        if lim.category == "malformed_syntax" and "broken_syntax.py" in lim.file_path
    ]
    assert len(syntax_lims) > 0
    assert "syntax error" in syntax_lims[0].description.lower()
