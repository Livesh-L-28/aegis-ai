"""Policy and authorization gateway for LogicFalcon FDE workflow execution."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.adapters.base import AdapterExecutionResult
from packages.review.fde.adapters.registry import AdapterRegistry
from packages.review.fde.models import (
    FdeEvidence,
    FdeStep,
    OperationCategory,
    StepRiskLevel,
    StepStatus,
)


class PolicyViolationError(PermissionError):
    """Raised when an operation violates security policy or lacks authorization."""
    pass


@dataclass
class PolicyAuditRecord:
    """Tamper-evident audit record for every evaluated operation."""

    timestamp: datetime
    mission_id: str
    step_id: str
    adapter_id: str
    operation: str
    target: str
    risk_level: StepRiskLevel
    operation_category: OperationCategory
    approved: bool
    allowed: bool
    reason: str
    parameters_digest: str


class PolicyGateway:
    """Enforces least privilege, parameter-bound approval, and safety boundaries."""

    def __init__(self, registry: AdapterRegistry, allow_high_risk_mutations: bool = False) -> None:
        self.registry = registry
        self.allow_high_risk_mutations = allow_high_risk_mutations
        self.audit_log: list[PolicyAuditRecord] = []
        self._approved_tokens: set[str] = set()

    @staticmethod
    def compute_approval_token(
        mission_id: str,
        step_id: str,
        adapter_id: str,
        operation: str,
        target: str,
        params: dict[str, Any],
    ) -> str:
        """Computes a deterministic cryptographic hash binding approval to the exact execution parameters."""
        canonical_params = json.dumps(params, sort_keys=True, default=str)
        payload = f"{mission_id}:{step_id}:{adapter_id}:{operation}:{target}:{canonical_params}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def grant_approval(
        self,
        mission_id: str,
        step_id: str,
        adapter_id: str,
        operation: str,
        target: str,
        params: dict[str, Any],
    ) -> str:
        """Explicitly authorizes an exact step and parameters, returning the approval token."""
        token = self.compute_approval_token(mission_id, step_id, adapter_id, operation, target, params)
        self._approved_tokens.add(token)
        return token

    def revoke_approval(self, token: str) -> None:
        """Revokes an existing approval token."""
        self._approved_tokens.discard(token)

    def is_approved(
        self,
        mission_id: str,
        step_id: str,
        adapter_id: str,
        operation: str,
        target: str,
        params: dict[str, Any],
    ) -> bool:
        """Verifies if an exact operation and parameters have been explicitly approved."""
        token = self.compute_approval_token(mission_id, step_id, adapter_id, operation, target, params)
        return token in self._approved_tokens

    def execute_step(
        self,
        mission_id: str,
        step: FdeStep,
        adapter_id: str,
        operation: str,
        params: dict[str, Any],
        approval_token: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        """Evaluates policy, checks approval, and safely dispatches to the registered adapter."""
        adapter = self.registry.get(adapter_id)
        if not adapter:
            raise PolicyViolationError(f"Adapter '{adapter_id}' is not registered in the system.")

        capability = adapter.get_capability(operation)
        if not capability:
            raise PolicyViolationError(f"Operation '{operation}' is not supported by adapter '{adapter_id}'.")

        # 1. Determine approval requirements
        needs_approval = (
            step.requires_approval
            or capability.requires_approval
            or step.risk_level in (StepRiskLevel.HIGH, StepRiskLevel.CRITICAL)
            or capability.risk_level in (StepRiskLevel.HIGH, StepRiskLevel.CRITICAL)
            or capability.operation_category in (
                OperationCategory.CONSEQUENTIAL_MUTATION,
                OperationCategory.DESTRUCTIVE,
            )
        )

        params_digest = hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        is_valid_token = False

        if needs_approval:
            expected_token = self.compute_approval_token(
                mission_id=mission_id,
                step_id=step.id,
                adapter_id=adapter_id,
                operation=operation,
                target=step.target,
                params=params,
            )
            is_valid_token = (
                approval_token == expected_token or expected_token in self._approved_tokens
            )
            if not is_valid_token:
                audit = PolicyAuditRecord(
                    timestamp=datetime.now(UTC),
                    mission_id=mission_id,
                    step_id=step.id,
                    adapter_id=adapter_id,
                    operation=operation,
                    target=step.target,
                    risk_level=step.risk_level,
                    operation_category=capability.operation_category,
                    approved=False,
                    allowed=False,
                    reason="Operation requires explicit approval for exact step and parameters.",
                    parameters_digest=params_digest,
                )
                self.audit_log.append(audit)
                raise PolicyViolationError(
                    f"Policy Gateway Blocked Step '{step.id}': Operation '{operation}' on '{step.target}' "
                    f"requires explicit human approval token matching the exact execution parameters."
                )

        # 2. Check for destructive operation policy
        if (
            capability.operation_category == OperationCategory.DESTRUCTIVE
            and not self.allow_high_risk_mutations
        ):
            audit = PolicyAuditRecord(
                timestamp=datetime.now(UTC),
                mission_id=mission_id,
                step_id=step.id,
                adapter_id=adapter_id,
                operation=operation,
                target=step.target,
                risk_level=step.risk_level,
                operation_category=capability.operation_category,
                approved=is_valid_token,
                allowed=False,
                reason="Destructive operations are strictly prohibited by policy.",
                parameters_digest=params_digest,
            )
            self.audit_log.append(audit)
            raise PolicyViolationError(
                f"Policy Gateway Blocked Step '{step.id}': Destructive operations are prohibited."
            )

        # 3. Log allowed execution audit record
        audit = PolicyAuditRecord(
            timestamp=datetime.now(UTC),
            mission_id=mission_id,
            step_id=step.id,
            adapter_id=adapter_id,
            operation=operation,
            target=step.target,
            risk_level=step.risk_level,
            operation_category=capability.operation_category,
            approved=is_valid_token if needs_approval else True,
            allowed=True,
            reason="Authorized by policy gateway.",
            parameters_digest=params_digest,
        )
        self.audit_log.append(audit)

        # 4. Dispatch to adapter
        result = adapter.execute(operation=operation, params=params, context=context)

        # 5. Attach structured sanitized evidence record if missing
        if result.evidence is None:
            raw_out_str = redact_secrets_in_text(json.dumps(result.output, default=str))
            result.evidence = FdeEvidence(
                mission_id=mission_id,
                step_id=step.id,
                adapter_name=adapter_id,
                operation=operation,
                status=StepStatus.SUCCEEDED if result.success else StepStatus.FAILED,
                sanitized_output=raw_out_str[:25_000],
                metadata={
                    "target": step.target,
                    "execution_time_seconds": result.execution_time_seconds,
                    "error": result.error,
                },
                timestamp=datetime.now(UTC),
            )

        return result
