"""Regression tests for RES-02: Cooperative cancellation correctness and tenant isolation."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import Organization
from apps.api.app.schemas.domain import ReviewCreateRequest
from apps.api.app.services.review import CodeReviewService
from packages.review.domain.models import ReviewStatus
from packages.review.engine import LocalReviewEngine, ReviewCancelledException

SAMPLE_DIFF = """diff --git a/pkg/service.py b/pkg/service.py
new file mode 100644
--- /dev/null
+++ b/pkg/service.py
@@ -0,0 +1,5 @@
+def compute():
+    eval("bad")
+    return 100
+"""


@pytest.mark.asyncio
async def test_engine_cooperative_cancellation_token() -> None:
    engine = LocalReviewEngine(repo_root=".")

    # 1. Token already cancelled before start
    with pytest.raises(ReviewCancelledException, match="Review cancelled before processing"):
        await engine.review_diff_async(diff_text=SAMPLE_DIFF, cancellation_token=lambda: True)

    # 2. Token cancellation during files
    counter = 0

    def cancel_after_first() -> bool:
        nonlocal counter
        counter += 1
        return counter > 1

    with pytest.raises(ReviewCancelledException):
        await engine.review_diff_async(diff_text=SAMPLE_DIFF, cancellation_token=cancel_after_first)


@pytest.mark.asyncio
async def test_service_cancellation_before_execution(db_session: AsyncSession) -> None:
    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="Cancel Org", slug="cancel-org")
    db_session.add(org)
    await db_session.commit()

    service = CodeReviewService(db_session)
    session = await service.create_review_session(
        organization_id=org_id,
        payload=ReviewCreateRequest(repository_name="test", diff_text=SAMPLE_DIFF),
    )

    # Cancel session immediately before execution starts
    await service.cancel_session(session.id, org_id, reason="Cancelled before exec")

    # Run execute_review
    res = await service.execute_review(session.id, org_id, diff_text=SAMPLE_DIFF)
    assert res.status == ReviewStatus.CANCELLED.value
    assert res.cancellation_reason == "Cancelled before exec"


@pytest.mark.asyncio
async def test_service_cancellation_near_completion_cannot_be_overwritten(db_session: AsyncSession) -> None:
    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="Race Org", slug="race-org")
    db_session.add(org)
    await db_session.commit()

    service = CodeReviewService(db_session)
    session = await service.create_review_session(
        organization_id=org_id,
        payload=ReviewCreateRequest(repository_name="test", diff_text=SAMPLE_DIFF),
    )

    # Signal in-memory cancellation while review is processing
    CodeReviewService.signal_cancellation(session.id, org_id)

    res = await service.execute_review(session.id, org_id, diff_text=SAMPLE_DIFF)
    assert res.status == ReviewStatus.CANCELLED.value

    # Refresh from DB to verify it was never overwritten by COMPLETED
    refreshed = await service.get_session(session.id, org_id)
    assert refreshed is not None
    assert refreshed.status == ReviewStatus.CANCELLED.value


@pytest.mark.asyncio
async def test_cancellation_tenant_scoping(db_session: AsyncSession) -> None:
    org1_id = uuid.uuid4()
    org2_id = uuid.uuid4()
    db_session.add_all([
        Organization(id=org1_id, name="Org 1", slug="org-1"),
        Organization(id=org2_id, name="Org 2", slug="org-2"),
    ])
    await db_session.commit()

    service = CodeReviewService(db_session)
    session1 = await service.create_review_session(
        organization_id=org1_id,
        payload=ReviewCreateRequest(repository_name="repo1", diff_text=SAMPLE_DIFF),
    )

    # Cancel for Org 1
    CodeReviewService.signal_cancellation(session1.id, org1_id)

    # Verify Org 2 is NOT affected
    assert CodeReviewService.is_cancelled(session1.id, org1_id) is True
    assert CodeReviewService.is_cancelled(session1.id, org2_id) is False

    CodeReviewService.clear_cancellation(session1.id, org1_id)
