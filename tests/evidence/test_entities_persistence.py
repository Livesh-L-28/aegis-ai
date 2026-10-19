"""Tests for Phase 1B persistent SQLAlchemy entities in the Engineering Evidence Graph."""

from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import (
    CodeDependencyEdgeEntity,
    CodeSymbolNodeEntity,
    EngineeringEvidenceRecordEntity,
    Organization,
    Project,
    RepositoryEntity,
    ReviewFindingEntity,
    ReviewSessionEntity,
    RevisionEntity,
    SourceFileNodeEntity,
)


@pytest.mark.asyncio
async def test_repository_hierarchy_persistence(db_session: AsyncSession) -> None:
    org = Organization(name="Evidence Org", slug=f"ev-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Core Engine", slug="core-engine")
    db_session.add(proj)
    await db_session.flush()

    repo = RepositoryEntity(
        organization_id=org.id,
        project_id=proj.id,
        name="aegis-core",
        slug="aegis-core",
        default_branch="main",
        repo_url="https://github.com/aegis/core",
    )
    db_session.add(repo)
    await db_session.flush()

    rev = RevisionEntity(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha="a" * 40,
        author="alice@example.com",
        commit_message="Initial commit",
    )
    db_session.add(rev)
    await db_session.flush()

    file_node = SourceFileNodeEntity(
        organization_id=org.id,
        repository_id=repo.id,
        revision_id=rev.id,
        file_path="apps/api/app/main.py",
        classification="SOURCE",
        language="python",
        content_hash="b" * 64,
        size_bytes=1024,
    )
    db_session.add(file_node)
    await db_session.flush()

    sym = CodeSymbolNodeEntity(
        organization_id=org.id,
        file_node_id=file_node.id,
        name="create_application",
        qualified_name="apps.api.app.main.create_application",
        symbol_type="FUNCTION",
        start_line=48,
        end_line=134,
        signature="def create_application() -> FastAPI",
        docstring_summary="Initializes application",
        embedding=[0.05] * 64,
    )
    db_session.add(sym)
    await db_session.flush()

    dep = CodeDependencyEdgeEntity(
        organization_id=org.id,
        repository_id=repo.id,
        revision_id=rev.id,
        source_file_path="apps/api/app/main.py",
        target_module="apps.api.app.core.config",
        imported_symbols=["settings"],
        edge_type="IMPORT",
    )
    db_session.add(dep)
    await db_session.flush()

    ev_record = EngineeringEvidenceRecordEntity(
        organization_id=org.id,
        repository_id=repo.id,
        revision_id=rev.id,
        evidence_type="STATIC_ANALYSIS",
        provenance_source="ast_security",
        file_path="apps/api/app/main.py",
        start_line=48,
        end_line=134,
        symbol_name="create_application",
        content="Clean entrypoint definition",
        confidence=1.0,
        content_hash="c" * 64,
        validation_status="VALIDATED",
    )
    db_session.add(ev_record)
    await db_session.flush()

    # Query back to verify relationships
    stmt = select(RepositoryEntity).where(RepositoryEntity.id == repo.id)
    res = await db_session.execute(stmt)
    loaded_repo = res.scalar_one()
    assert loaded_repo.slug == "aegis-core"


@pytest.mark.asyncio
async def test_repository_unique_slug_per_project(db_session: AsyncSession) -> None:
    org = Organization(name="Org Dup", slug=f"org-dup-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Project 1", slug="proj-1")
    db_session.add(proj)
    await db_session.flush()

    r1 = RepositoryEntity(organization_id=org.id, project_id=proj.id, name="Repo A", slug="same-slug")
    db_session.add(r1)
    await db_session.flush()

    r2 = RepositoryEntity(organization_id=org.id, project_id=proj.id, name="Repo B", slug="same-slug")
    db_session.add(r2)
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_revision_unique_commit_per_repository(db_session: AsyncSession) -> None:
    org = Organization(name="Org Rev", slug=f"org-rev-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Project Rev", slug="proj-rev")
    db_session.add(proj)
    await db_session.flush()

    repo = RepositoryEntity(organization_id=org.id, project_id=proj.id, name="Repo Rev", slug="repo-rev")
    db_session.add(repo)
    await db_session.flush()

    rev1 = RevisionEntity(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha="deadbeef" * 5,
        author="alice",
    )
    db_session.add(rev1)
    await db_session.flush()

    rev2 = RevisionEntity(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha="deadbeef" * 5,
        author="bob",
    )
    db_session.add(rev2)
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_review_finding_linked_to_evidence_record(db_session: AsyncSession) -> None:
    org = Organization(name="Org RevLink", slug=f"org-revlink-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    ev_rec = EngineeringEvidenceRecordEntity(
        organization_id=org.id,
        evidence_type="STATIC_ANALYSIS",
        provenance_source="ast_security",
        file_path="apps/api/app/main.py",
        start_line=10,
        end_line=12,
        content="Dangerous exec found",
        confidence=1.0,
        content_hash="d" * 64,
        validation_status="VALIDATED",
    )
    db_session.add(ev_rec)
    await db_session.flush()

    sess = ReviewSessionEntity(
        organization_id=org.id,
        repository_name="aegis-core",
        review_type="LOCAL",
        status="COMPLETED",
    )
    db_session.add(sess)
    await db_session.flush()

    finding = ReviewFindingEntity(
        review_id=sess.id,
        organization_id=org.id,
        evidence_record_id=ev_rec.id,
        file_path="apps/api/app/main.py",
        start_line=10,
        end_line=12,
        rule_id="SEC-001",
        title="Dynamic Execution",
        message="exec call detected",
        severity="CRITICAL",
        category="SECURITY",
        origin="STATIC_ANALYSIS",
        deduplication_hash="hash1234",
    )
    db_session.add(finding)
    await db_session.flush()

    # Query back finding with linked evidence_record
    stmt = select(ReviewFindingEntity).where(ReviewFindingEntity.id == finding.id)
    res = await db_session.execute(stmt)
    loaded = res.scalar_one()
    assert loaded.evidence_record_id == ev_rec.id
