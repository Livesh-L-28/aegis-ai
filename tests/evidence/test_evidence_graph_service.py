"""Comprehensive tests for Phase 1C EvidenceGraphService and persistent indexing."""

from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import Organization, Project
from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.evidence.graph_models import (
    EvidenceRecord,
    ProvenanceTag,
    ValidationStatus,
)


@pytest.fixture
def test_org_project() -> tuple[UUID, UUID]:
    return uuid4(), uuid4()


@pytest.mark.asyncio
async def test_initial_indexing_and_ast_extraction(
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Test Org", slug=f"org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Test Proj", slug="test-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)

    files = {
        "pkg/math_ops.py": (
            "def add(a, b):\n"
            "    '''Add two numbers.'''\n"
            "    return a + b\n\n"
            "class Calculator:\n"
            "    def multiply(self, x, y):\n"
            "        return x * y\n"
        ),
        "tests/test_math.py": (
            "import pkg.math_ops\n\n"
            "def test_add():\n"
            "    assert pkg.math_ops.add(1, 2) == 3\n"
        ),
        "render_schema.json": '{"protected": true}',  # Must be ignored!
        "../../etc/passwd": "root:x:0:0",  # Traversal attempt, must be ignored!
    }

    repo, rev, indexed_count = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="calc-service",
        commit_sha="1111111111111111111111111111111111111111",
        author="developer@example.com",
        commit_message="feat: initial calculator",
        file_contents=files,
    )

    assert repo.slug == "calc-service"
    assert rev.commit_sha == "1111111111111111111111111111111111111111"
    # Only the 2 valid source/test files should be indexed
    assert indexed_count == 2

    # Verify symbols in pkg/math_ops.py
    symbols, total = await service.get_symbols_for_revision(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
        file_path="pkg/math_ops.py",
    )
    assert total == 3
    sym_names = {s.name for s in symbols}
    assert sym_names == {"add", "Calculator", "multiply"}


@pytest.mark.asyncio
async def test_content_hash_caching_and_revision_separation(
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Cache Org", slug=f"cache-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Cache Proj", slug="cache-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)

    # Revision 1
    r1_files = {
        "pkg/utils.py": "def helper():\n    return 42\n",
        "pkg/feature.py": "def v1_feature():\n    pass\n",
    }
    repo, rev1, count1 = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="versioned-repo",
        commit_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        file_contents=r1_files,
    )
    assert count1 == 2

    # Revision 2: utils.py unchanged, feature.py changed
    r2_files = {
        "pkg/utils.py": "def helper():\n    return 42\n",  # identical hash
        "pkg/feature.py": "def v2_feature():\n    pass\n",  # changed
    }
    _, rev2, count2 = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="versioned-repo",
        commit_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        parent_shas=["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        file_contents=r2_files,
    )
    assert count2 == 2

    # Symbols in rev1
    syms_r1_feat, _ = await service.get_symbols_for_revision(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev1.commit_sha,
        file_path="pkg/feature.py",
    )
    assert len(syms_r1_feat) == 1
    assert syms_r1_feat[0].name == "v1_feature"

    # Symbols in rev2 (feature.py has new symbol, utils.py has reused symbol)
    syms_r2_feat, _ = await service.get_symbols_for_revision(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev2.commit_sha,
        file_path="pkg/feature.py",
    )
    assert len(syms_r2_feat) == 1
    assert syms_r2_feat[0].name == "v2_feature"

    syms_r2_utils, _ = await service.get_symbols_for_revision(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev2.commit_sha,
        file_path="pkg/utils.py",
    )
    assert len(syms_r2_utils) == 1
    assert syms_r2_utils[0].name == "helper"


@pytest.mark.asyncio
async def test_indexing_idempotency_and_malformed_syntax(
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Idempotent Org", slug=f"idem-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Idem Proj", slug="idem-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)

    files = {
        "valid.py": "def ok(): pass\n",
        "broken.py": "def broken( invalid syntax here !!!:\n",
    }

    repo, rev, count = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="syntax-repo",
        commit_sha="cccccccccccccccccccccccccccccccccccccccc",
        file_contents=files,
    )
    assert count == 2

    # Re-indexing the exact same revision should be idempotent (0 newly indexed)
    _, _, count_again = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="syntax-repo",
        commit_sha="cccccccccccccccccccccccccccccccccccccccc",
        file_contents=files,
    )
    assert count_again == 0

    # Broken python file still created a node, but no symbols crashed the indexer
    syms, _ = await service.get_symbols_for_revision(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
        file_path="broken.py",
    )
    assert len(syms) == 0


@pytest.mark.asyncio
async def test_reverse_dependency_and_affected_tests_multi_hop(
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Dep Org", slug=f"dep-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Dep Proj", slug="dep-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)

    # Dependency chain:
    # tests/test_orders.py -> services/order_service.py -> models/order.py
    # and a cycle:
    # models/order.py -> models/customer.py -> models/order.py
    files = {
        "models/order.py": (
            "import models.customer\n\n"
            "class Order:\n"
            "    pass\n"
        ),
        "models/customer.py": (
            "import models.order\n\n"
            "class Customer:\n"
            "    pass\n"
        ),
        "services/order_service.py": (
            "from models.order import Order\n\n"
            "def place_order():\n"
            "    return Order()\n"
        ),
        "tests/test_orders.py": (
            "import services.order_service\n\n"
            "def test_place_order():\n"
            "    pass\n"
        ),
        "tests/test_unrelated.py": (
            "def test_other():\n"
            "    pass\n"
        ),
    }

    repo, rev, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="order-service",
        commit_sha="dddddddddddddddddddddddddddddddddddddddd",
        file_contents=files,
    )

    # Changing models/order.py should discover tests/test_orders.py via transitive reverse dependency
    affected = await service.get_affected_tests(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
        changed_files=["models/order.py"],
        max_depth=3,
    )

    assert "tests/test_orders.py" in affected
    assert "tests/test_unrelated.py" not in affected

    # Cycles (models/order <-> models/customer) must not cause infinite loops
    cycle_affected = await service.get_affected_tests(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
        changed_files=["models/customer.py"],
        max_depth=3,
    )
    assert "tests/test_orders.py" in cycle_affected


@pytest.mark.asyncio
async def test_evidence_record_lifecycle_and_tenant_scoping(
    db_session: AsyncSession,
) -> None:
    org1 = Organization(name="Tenant One", slug=f"t1-{uuid4().hex[:6]}")
    org2 = Organization(name="Tenant Two", slug=f"t2-{uuid4().hex[:6]}")
    db_session.add_all([org1, org2])
    await db_session.flush()

    proj = Project(organization_id=org1.id, name="Project 1", slug="proj-1")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)

    repo, rev, _ = await service.index_repository_revision(
        organization_id=org1.id,
        project_id=proj.id,
        repo_slug="app-repo",
        commit_sha="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        file_contents={"app.py": "def run(): pass\n"},
    )

    rec = EvidenceRecord(
        evidence_type="static_analysis",
        provenance=ProvenanceTag(source="bandit", tool_version="1.7.5"),
        file_path="app.py",
        start_line=1,
        end_line=1,
        symbol_name="run",
        content="assert statement used",
        structured_payload={"severity": "LOW"},
        confidence=0.95,
        content_hash="abc123hash",
        validation_status=ValidationStatus.VALIDATED,
    )

    persisted = await service.record_evidence(
        organization_id=org1.id,
        record=rec,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
    )
    assert persisted.id == rec.id
    assert persisted.organization_id == org1.id
    assert persisted.repository_id == repo.id

    # Tenant 1 sees the record
    items1, total1 = await service.list_evidence(
        organization_id=org1.id,
        repository_id=repo.id,
    )
    assert total1 == 1
    assert items1[0].id == rec.id

    # Tenant 2 cannot see Tenant 1's record
    items2, total2 = await service.list_evidence(
        organization_id=org2.id,
        repository_id=repo.id,
    )
    assert total2 == 0
    assert len(items2) == 0
