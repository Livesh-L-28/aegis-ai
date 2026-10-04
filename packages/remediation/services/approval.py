"""Phase 6 Approval Workflow Service: Explicit approval, expiration, hash binding, and separation of duties."""

from datetime import UTC, datetime, timedelta

from packages.remediation.domain.enums import ApprovalDecision, RemediationStatus
from packages.remediation.domain.models import RemediationApproval, RemediationProposal
from packages.security.policy import default_policy_engine
from packages.security.rbac import AuthenticatedPrincipal, Permission


class ApprovalWorkflowService:
    """Governs explicit human authorization of remediation proposals."""

    def __init__(self) -> None:
        self.policy_engine = default_policy_engine

    def approve_proposal(
        self,
        proposal: RemediationProposal,
        principal: AuthenticatedPrincipal,
        reason: str = "Authorized by on-call engineer following runbook verification",
    ) -> RemediationApproval:
        """Approve a remediation proposal.

        Enforces:
        - RBAC: Must possess REMEDIATION_APPROVE permission.
        - Separation of duties: Author cannot approve their own MEDIUM/HIGH proposals.
        - Expiration: Proposal cannot already be expired.
        - Deterministic binding: Binds approval directly to proposal.remediation_hash.
        """
        if not principal.has_permission(Permission.REMEDIATION_APPROVE):
            raise PermissionError(f"User {principal.user_id} lacks REMEDIATION_APPROVE permission.")

        now = datetime.now(UTC)
        if proposal.expires_at:
            exp = proposal.expires_at if proposal.expires_at.tzinfo else proposal.expires_at.replace(tzinfo=UTC)
            if now > exp:
                proposal.status = RemediationStatus.EXPIRED
                raise ValueError("Cannot approve expired remediation proposal.")

        # Separation of duties check
        policy_eval = self.policy_engine.evaluate_remediation_proposal(
            risk_level=proposal.risk_level,
            has_approval=True,
            approver_count=1,
            author_id=proposal.created_by,
            approver_id=principal.user_id,
        )
        if not policy_eval.allowed:
            raise PermissionError(f"Approval denied by policy: {policy_eval.reason}")

        current_hash = proposal.compute_remediation_hash()
        approval = RemediationApproval(
            remediation_id=proposal.id,
            organization_id=proposal.organization_id,
            approver_id=principal.user_id,
            decision=ApprovalDecision.APPROVED,
            reason=reason,
            policy_version=self.policy_engine.policy_version,
            remediation_hash=current_hash,
            created_at=now,
            expires_at=proposal.expires_at or (now + timedelta(hours=24)),
        )

        proposal.status = RemediationStatus.APPROVED
        proposal.remediation_hash = current_hash
        return approval

    def reject_proposal(
        self,
        proposal: RemediationProposal,
        principal: AuthenticatedPrincipal,
        reason: str,
    ) -> RemediationApproval:
        """Explicit rejection of a remediation proposal."""
        if not principal.has_permission(Permission.REMEDIATION_APPROVE):
            raise PermissionError(f"User {principal.user_id} lacks permission to reject proposal.")

        if not reason or not reason.strip():
            raise ValueError("Rejection reason must be provided.")

        now = datetime.now(UTC)
        approval = RemediationApproval(
            remediation_id=proposal.id,
            organization_id=proposal.organization_id,
            approver_id=principal.user_id,
            decision=ApprovalDecision.REJECTED,
            reason=reason,
            policy_version=self.policy_engine.policy_version,
            remediation_hash=proposal.remediation_hash,
            created_at=now,
            expires_at=now,
        )

        proposal.status = RemediationStatus.REJECTED
        return approval

    def verify_approval(
        self,
        proposal: RemediationProposal,
        approval: RemediationApproval,
    ) -> tuple[bool, str]:
        """Validates approval validity immediately prior to execution."""
        now = datetime.now(UTC)
        if now > approval.expires_at:
            return False, "Approval has expired."

        if approval.decision != ApprovalDecision.APPROVED:
            return False, f"Remediation is not approved (decision={approval.decision.value})."

        current_hash = proposal.compute_remediation_hash()
        if approval.remediation_hash != current_hash:
            return False, "Remediation content changed after approval was granted (hash mismatch)."

        return True, "Approval is valid"


default_approval_service = ApprovalWorkflowService()
