"""Phase 6 Unit Tests: Approval workflow, hash binding, expiration, and separation of duties."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from packages.remediation.domain.enums import (
    ApprovalDecision,
    RemediationActionType,
    RemediationStatus,
)
from packages.remediation.domain.models import RemediationAction, RemediationProposal
from packages.remediation.services.approval import ApprovalWorkflowService
from packages.security.policy import AIRiskLevel
from packages.security.rbac import AuthenticatedPrincipal, Role


def _build_test_proposal(author_id: str = "engineer-1", risk: AIRiskLevel = AIRiskLevel.HIGH) -> RemediationProposal:
    p = RemediationProposal(
        incident_id=uuid4(),
        organization_id=uuid4(),
        service_name="payment-service",
        title="Restart Payment Gateway",
        description="Restarting to clear connection state",
        root_cause_reference="Redis connection breakdown",
        risk_level=risk,
        created_by=author_id,
        actions=[
            RemediationAction(
                action_type=RemediationActionType.SERVICE_RESTART,
                target="payment-service",
                parameters={"service_name": "payment-service"},
                risk_level=risk,
            )
        ],
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    p.remediation_hash = p.compute_remediation_hash()
    return p


def test_authorized_approval_succeeds() -> None:
    service = ApprovalWorkflowService()
    proposal = _build_test_proposal(author_id="author-1")

    approver = AuthenticatedPrincipal(
        user_id="approver-2",
        email="approver@corp.com",
        roles=[Role.OWNER],
    )

    approval = service.approve_proposal(proposal, approver, reason="Runbook verified")
    assert approval.decision == ApprovalDecision.APPROVED
    assert proposal.status == RemediationStatus.APPROVED
    assert approval.remediation_hash == proposal.remediation_hash


def test_unauthorized_user_cannot_approve() -> None:
    service = ApprovalWorkflowService()
    proposal = _build_test_proposal()

    viewer = AuthenticatedPrincipal(
        user_id="viewer-1",
        email="viewer@corp.com",
        roles=[Role.VIEWER],
    )

    with pytest.raises(PermissionError, match="lacks REMEDIATION_APPROVE permission"):
        service.approve_proposal(proposal, viewer)


def test_separation_of_duties_enforced() -> None:
    service = ApprovalWorkflowService()
    proposal = _build_test_proposal(author_id="author-1", risk=AIRiskLevel.HIGH)

    # Author attempts to approve their own high-risk proposal
    author_approver = AuthenticatedPrincipal(
        user_id="author-1",
        email="author@corp.com",
        roles=[Role.OWNER],
    )

    with pytest.raises(PermissionError, match="Separation of duties violation"):
        service.approve_proposal(proposal, author_approver)


def test_approval_invalidated_when_proposal_modified() -> None:
    service = ApprovalWorkflowService()
    proposal = _build_test_proposal(author_id="author-1")

    approver = AuthenticatedPrincipal(
        user_id="approver-2",
        email="approver@corp.com",
        roles=[Role.ADMIN],
    )

    approval = service.approve_proposal(proposal, approver)
    valid, _msg = service.verify_approval(proposal, approval)
    assert valid

    # Modify proposal action parameter
    proposal.actions[0].parameters["extra_flag"] = "dangerous"
    invalid, err = service.verify_approval(proposal, approval)
    assert not invalid
    assert "hash mismatch" in err.lower()


def test_expired_approval_rejected() -> None:
    service = ApprovalWorkflowService()
    proposal = _build_test_proposal(author_id="author-1")
    proposal.expires_at = datetime.now(UTC) - timedelta(minutes=5)

    approver = AuthenticatedPrincipal(
        user_id="approver-2",
        email="approver@corp.com",
        roles=[Role.OWNER],
    )

    with pytest.raises(ValueError, match="Cannot approve expired remediation proposal"):
        service.approve_proposal(proposal, approver)
