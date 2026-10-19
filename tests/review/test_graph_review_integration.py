"""Tests for Phase 1D Review Engine and AI Factuality Gate integration with the Engineering Evidence Graph."""

from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import Organization, Project
from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.review.ai.context_builder import BoundedReviewContext
from packages.review.ai.reviewer import AIReviewEngine
from packages.review.ai.schemas import AIReviewFindingItem
from packages.review.domain.models import ValidationStatus
from packages.review.engine import LocalReviewEngine, ReviewConfig


@pytest.fixture
def mock_context() -> BoundedReviewContext:
    return BoundedReviewContext(
        repository_name="test-repo",
        changed_files=["app/main.py", "app/utils.py"],
        changed_symbols=[
            {
                "file_path": "app/main.py",
                "name": "calculate_total",
                "qualified_name": "calculate_total",
                "start_line": 10,
                "end_line": 20,
            },
            {
                "file_path": "app/main.py",
                "name": "OrderProcessor",
                "qualified_name": "OrderProcessor",
                "start_line": 25,
                "end_line": 50,
            },
        ],
        dependencies={},
        affected_tests=[],
        diff_snippets=[],
    )


@pytest.mark.asyncio
async def test_factuality_gate_valid_symbol(mock_context: BoundedReviewContext) -> None:
    engine = AIReviewEngine()

    raw_items = [
        AIReviewFindingItem(
            file_path="app/main.py",
            start_line=12,
            end_line=15,
            symbol_name="calculate_total",
            title="Potential rounding error",
            description="Floating point precision may cause inaccurate order totals.",
            technical_evidence="sum() over float values",
        )
    ]

    findings = engine._validate_and_normalize_findings(
        raw_findings=raw_items,
        context=mock_context,
        review_id=uuid4(),
    )

    assert len(findings) == 1
    assert findings[0].validation_status == ValidationStatus.VALIDATED
    assert findings[0].location.symbol_name == "calculate_total"


@pytest.mark.asyncio
async def test_factuality_gate_rejects_fabricated_symbol(mock_context: BoundedReviewContext) -> None:
    engine = AIReviewEngine()

    raw_items = [
        AIReviewFindingItem(
            file_path="app/main.py",
            start_line=15,
            end_line=20,
            symbol_name="non_existent_security_bypass",  # Fabricated symbol!
            title="Insecure deserialization",
            description="Pickle loaded insecurely in non_existent_security_bypass.",
            technical_evidence="pickle.loads",
        )
    ]

    findings = engine._validate_and_normalize_findings(
        raw_findings=raw_items,
        context=mock_context,
        review_id=uuid4(),
    )

    assert len(findings) == 1
    # Fabricated symbol must be flagged as REJECTED_LOCATION
    assert findings[0].validation_status == ValidationStatus.REJECTED_LOCATION


@pytest.mark.asyncio
async def test_factuality_gate_rejects_invalid_line_range(mock_context: BoundedReviewContext) -> None:
    engine = AIReviewEngine()

    raw_items = [
        AIReviewFindingItem(
            file_path="app/main.py",
            start_line=-5,  # Invalid negative line!
            end_line=10,
            title="Negative line bug",
            description="Bug description.",
            technical_evidence="None",
        ),
        AIReviewFindingItem(
            file_path="app/main.py",
            start_line=50,
            end_line=30,  # end < start!
            title="Inverted line range",
            description="Inverted range.",
            technical_evidence="None",
        ),
    ]

    findings = engine._validate_and_normalize_findings(
        raw_findings=raw_items,
        context=mock_context,
        review_id=uuid4(),
    )

    assert len(findings) == 2
    assert findings[0].validation_status == ValidationStatus.REJECTED_LOCATION
    assert findings[1].validation_status == ValidationStatus.REJECTED_LOCATION


@pytest.mark.asyncio
async def test_factuality_gate_unverified_when_symbols_absent(mock_context: BoundedReviewContext) -> None:
    engine = AIReviewEngine()

    raw_items = [
        AIReviewFindingItem(
            file_path="app/utils.py",  # utils.py has NO symbols in mock_context.changed_symbols
            start_line=5,
            end_line=10,
            title="Unchecked dict access",
            description="Access without check.",
            technical_evidence="d['key']",
        )
    ]

    findings = engine._validate_and_normalize_findings(
        raw_findings=raw_items,
        context=mock_context,
        review_id=uuid4(),
    )

    assert len(findings) == 1
    assert findings[0].validation_status == ValidationStatus.UNVERIFIED


@pytest.mark.asyncio
async def test_review_engine_integrates_persisted_affected_tests(
    db_session: AsyncSession,
    tmp_path: Path,
) -> None:
    org = Organization(name="Review Org", slug=f"rev-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Rev Proj", slug="rev-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)

    # Index repository revision in the database
    files = {
        "services/payment.py": "import models.card\ndef charge(): pass\n",
        "tests/test_payment.py": "import services.payment\ndef test_charge(): pass\n",
    }
    repo, rev, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="payment-repo",
        commit_sha="f" * 40,
        file_contents=files,
    )

    # Configure LocalReviewEngine with evidence_service
    config = ReviewConfig(
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
    )
    engine = LocalReviewEngine(
        repo_root=tmp_path,
        config=config,
        evidence_service=service,
    )

    diff = (
        "diff --git a/services/payment.py b/services/payment.py\n"
        "--- a/services/payment.py\n"
        "+++ b/services/payment.py\n"
        "@@ -1,2 +1,3 @@\n"
        " import models.card\n"
        "+# extra comment\n"
        " def charge(): pass\n"
    )

    report = await engine.review_diff_async(
        diff_text=diff,
        organization_id=org.id,
        repository_id=repo.id,
        commit_sha=rev.commit_sha,
    )

    # Graph service must discover tests/test_payment.py for services/payment.py
    assert "tests/test_payment.py" in report.affected_artifacts.affected_tests


@pytest.mark.asyncio
async def test_review_engine_fallback_when_graph_service_fails(
    tmp_path: Path,
) -> None:
    broken_service = AsyncMock()
    broken_service.get_affected_tests.side_effect = RuntimeError("Database connection lost")

    config = ReviewConfig(
        organization_id=uuid4(),
        repository_id=uuid4(),
        commit_sha="a" * 40,
    )
    engine = LocalReviewEngine(
        repo_root=tmp_path,
        config=config,
        evidence_service=broken_service,
    )

    diff = (
        "diff --git a/file.py b/file.py\n"
        "--- a/file.py\n"
        "+++ b/file.py\n"
        "@@ -1,1 +1,2 @@\n"
        "+print('hello')\n"
    )

    # Must complete review cleanly via in-memory fallback without raising exception
    report = await engine.review_diff_async(diff_text=diff)
    assert report is not None
    assert isinstance(report.files_reviewed, list)
