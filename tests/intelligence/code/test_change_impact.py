"""Unit tests for Phase 2F Change-Impact Analysis and Intelligent Test Selection."""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.code.impact_analysis import (
    ChangeImpactAnalyzer,
    ImpactRiskLevel,
)


@pytest.mark.asyncio
async def test_change_impact_empty_files() -> None:
    service = MagicMock(spec=EvidenceGraphService)
    analyzer = ChangeImpactAnalyzer(service)

    report = await analyzer.analyze_impact(
        organization_id=uuid4(),
        repository_id=uuid4(),
        commit_sha="a" * 40,
        changed_files=[],
    )

    assert report.risk_level == ImpactRiskLevel.LOW
    assert report.changed_files == []
    assert "No changed files specified." in report.risk_reasons


@pytest.mark.asyncio
async def test_change_impact_critical_risk_classification() -> None:
    service = MagicMock(spec=EvidenceGraphService)
    service.get_symbols_for_revision = AsyncMock(return_value=([], 0))
    service.get_affected_tests = AsyncMock(return_value=["tests/security/test_auth.py"])

    analyzer = ChangeImpactAnalyzer(service)

    # Modifying both security and database migrations elevates risk to CRITICAL
    changed = [
        "apps/api/app/security/rbac.py",
        "alembic/versions/0008_migration.py",
    ]

    report = await analyzer.analyze_impact(
        organization_id=uuid4(),
        repository_id=uuid4(),
        commit_sha="b" * 40,
        changed_files=changed,
    )

    assert report.risk_level == ImpactRiskLevel.CRITICAL
    assert any("migration" in r.lower() for r in report.risk_reasons)
    assert any("security" in r.lower() for r in report.risk_reasons)
    assert "tests/security/test_auth.py" in report.affected_tests
    assert "tests/security/test_auth.py" in report.selection_explanations


@pytest.mark.asyncio
async def test_change_impact_api_and_tests_selection() -> None:
    service = MagicMock(spec=EvidenceGraphService)
    service.get_symbols_for_revision = AsyncMock(return_value=([], 0))
    service.get_affected_tests = AsyncMock(
        return_value=[
            "tests/api/test_orders.py",
            "tests/integration/test_orders_e2e.py",
        ]
    )

    analyzer = ChangeImpactAnalyzer(service)

    changed = [
        "apps/api/app/api/v1/endpoints/orders.py",
    ]

    report = await analyzer.analyze_impact(
        organization_id=uuid4(),
        repository_id=uuid4(),
        commit_sha="c" * 40,
        changed_files=changed,
    )

    assert report.risk_level == ImpactRiskLevel.HIGH
    assert any("endpoint" in r.lower() or "api" in r.lower() for r in report.risk_reasons)
    assert len(report.affected_tests) == 2
    assert report.confidence >= 0.9
