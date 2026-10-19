"""Unit tests for Phase 2D System Intelligence extraction (APIs, models, migrations, configs)."""

from packages.intelligence.code.system_intelligence import SystemIntelligenceExtractor


def test_fastapi_route_extraction() -> None:
    source_code = """
from fastapi import APIRouter, Depends
from apps.api.app.schemas.domain import UserResponse

router = APIRouter(prefix="/users")

@router.get("/{user_id}", response_model=UserResponse)
async def get_user_by_id(user_id: str):
    return {"id": user_id}

@router.post("/", response_model=UserResponse)
async def create_new_user(payload: dict):
    return payload
"""
    report = SystemIntelligenceExtractor.extract_from_file("apps/api/app/api/v1/endpoints/users.py", source_code)

    assert len(report.api_endpoints) == 2
    paths = {ep.route_path: ep for ep in report.api_endpoints}

    assert "/{user_id}" in paths
    assert paths["/{user_id}"].http_method == "GET"
    assert paths["/{user_id}"].handler_name == "get_user_by_id"
    assert paths["/{user_id}"].response_model == "UserResponse"

    assert "/" in paths
    assert paths["/"].http_method == "POST"
    assert paths["/"].handler_name == "create_new_user"


def test_client_api_call_extraction() -> None:
    source_code = """
import axios from 'axios';

export async function fetchInventory() {
    const res = await fetch("/api/v1/inventory/items");
    return res.json();
}

export async function updateItem(id: string, data: any) {
    return axios.put("/api/v1/inventory/items/" + id, data);
}
"""
    report = SystemIntelligenceExtractor.extract_from_file("src/api/client.ts", source_code)

    assert len(report.client_api_calls) >= 1
    paths = [cl.route_path for cl in report.client_api_calls]
    assert "/api/v1/inventory/items" in paths


def test_sqlalchemy_model_extraction() -> None:
    source_code = """
from sqlalchemy import Column, String, Integer
from apps.api.app.models.base import Base

class OrderEntity(Base):
    __tablename__ = "orders"

    id: str = Column(String, primary_key=True)
    status: str = Column(String, nullable=False)
    total_amount: int = Column(Integer)
"""
    report = SystemIntelligenceExtractor.extract_from_file("apps/api/app/models/orders.py", source_code)

    assert len(report.database_models) == 1
    model = report.database_models[0]
    assert model.class_name == "OrderEntity"
    assert model.table_name == "orders"
    assert "status" in model.columns or "id" in model.columns


def test_alembic_migration_extraction() -> None:
    source_code = """
\"\"\"add users table\"\"\"
revision = '0008_add_users'
down_revision = '0007_engineering_evidence_graph'

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table('users', sa.Column('id', sa.String()))

def downgrade():
    pass
"""
    report = SystemIntelligenceExtractor.extract_from_file("alembic/versions/0008_add_users.py", source_code)

    assert len(report.migrations) == 1
    mig = report.migrations[0]
    assert mig.revision_id == "0008_add_users"
    assert mig.down_revision_id == "0007_engineering_evidence_graph"
    assert "users" in mig.tables_created


def test_config_and_secret_safety() -> None:
    py_source = """
import os

db_url = os.environ.get("DATABASE_URL")
api_key = os.getenv("STRIPE_SECRET_KEY", "super-secret-12345")
"""
    js_source = """
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;
"""
    py_report = SystemIntelligenceExtractor.extract_from_file("app/config.py", py_source)
    js_report = SystemIntelligenceExtractor.extract_from_file("src/config.ts", js_source)

    py_keys = [cf.config_key for cf in py_report.config_references]
    js_keys = [cf.config_key for cf in js_report.config_references]

    assert "DATABASE_URL" in py_keys
    assert "STRIPE_SECRET_KEY" in py_keys
    assert "PORT" in js_keys
    assert "JWT_SECRET" in js_keys

    # Critical Security Check: Ensure sensitive secret value "super-secret-12345" is NOT stored
    for cf in py_report.config_references:
        assert "super-secret-12345" not in cf.config_key
        assert cf.config_key in ("DATABASE_URL", "STRIPE_SECRET_KEY")
