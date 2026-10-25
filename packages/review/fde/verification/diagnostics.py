"""Automated failure diagnosis and evidence correlation for LogicFalcon FDE."""

from dataclasses import dataclass, field
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.models import PreflightReport
from packages.review.fde.orchestration.orchestrator import StepExecutionSummary
from packages.review.fde.verification.postconditions import (
    PostconditionResult,
    VerificationOutcome,
)


@dataclass
class DiagnosticHypothesis:
    """Evidence-backed explanation of an observed deployment or execution failure."""

    title: str
    hypothesis: str
    confidence: float  # 0.0 to 1.0
    evidence_sources: list[str] = field(default_factory=list)
    recommended_action: str = ""
    is_speculative: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "hypothesis": self.hypothesis,
            "confidence": round(self.confidence, 2),
            "evidence_sources": self.evidence_sources,
            "recommended_action": self.recommended_action,
            "is_speculative": self.is_speculative,
        }


class FailureDiagnoser:
    """Correlates failed steps, postconditions, and preflight findings to diagnose failures."""

    def diagnose(
        self,
        failed_steps: list[StepExecutionSummary],
        postcondition_results: list[PostconditionResult] | None = None,
        preflight_report: PreflightReport | None = None,
    ) -> list[DiagnosticHypothesis]:
        """Produces evidence-backed hypotheses for all observed step failures."""
        hypotheses: list[DiagnosticHypothesis] = []
        pc_results = postcondition_results or []

        for step in failed_steps:
            err = step.error or ""
            err_lower = err.lower()

            # 1. Connection Refused / Service Down
            if "connect error" in err_lower or "connection refused" in err_lower or "unreachable" in err_lower:
                evidence = [f"Step '{step.step_id}' error: {redact_secrets_in_text(err)}"]
                if preflight_report and any("port" in f.category.lower() for f in preflight_report.findings):
                    evidence.append("Preflight port probe detected port binding or occupancy issues.")

                hypotheses.append(
                    DiagnosticHypothesis(
                        title=f"Service Unreachable for Step '{step.step_id}'",
                        hypothesis=(
                            f"The target service for step '{step.step_id}' at '{step.target}' "
                            f"is not running or not listening on the declared port."
                        ),
                        confidence=0.92,
                        evidence_sources=evidence,
                        recommended_action=(
                            f"Verify that the container or background process providing '{step.target}' "
                            f"is running and bound to the expected host interface."
                        ),
                        is_speculative=False,
                    )
                )

            # 2. Timeout
            elif "timeout" in err_lower or "timed out" in err_lower:
                hypotheses.append(
                    DiagnosticHypothesis(
                        title=f"Operation Timeout in Step '{step.step_id}'",
                        hypothesis=(
                            f"Step '{step.step_id}' failed to complete within its bounded execution window "
                            f"({step.execution_time_seconds:.1f}s)."
                        ),
                        confidence=0.88,
                        evidence_sources=[f"Execution timed out: {redact_secrets_in_text(err)}"],
                        recommended_action="Check host resource utilization, database locks, or external service latency.",
                        is_speculative=False,
                    )
                )

            # 3. Policy Gateway Blocked
            elif "policy gateway" in err_lower or "human approval" in err_lower:
                hypotheses.append(
                    DiagnosticHypothesis(
                        title=f"Authorization Policy Block in Step '{step.step_id}'",
                        hypothesis=(
                            f"Step '{step.step_id}' attempted a consequential or high-risk mutation "
                            f"without a valid parameter-bound human approval token."
                        ),
                        confidence=1.0,
                        evidence_sources=[err],
                        recommended_action=(
                            "Operator must review the intended operation parameters and issue an explicit "
                            "approval token before executing this step."
                        ),
                        is_speculative=False,
                    )
                )

            # 4. General / Postcondition failure
            else:
                related_pcs = [pc for pc in pc_results if pc.outcome == VerificationOutcome.FAILED]
                evidence = [f"Error: {redact_secrets_in_text(err)}"]
                for pc in related_pcs:
                    evidence.append(f"Postcondition '{pc.assertion_type}' failed on '{pc.target}': {pc.details}")

                hypotheses.append(
                    DiagnosticHypothesis(
                        title=f"Functional Failure in Step '{step.step_id}'",
                        hypothesis=(
                            f"Step '{step.step_id}' operation '{step.operation}' failed to meet postconditions. "
                            f"Root cause cannot be definitively established from available telemetry alone."
                        ),
                        confidence=0.65,
                        evidence_sources=evidence,
                        recommended_action="Inspect full application logs and diagnostic output for detailed stack traces.",
                        is_speculative=True,
                    )
                )

        return hypotheses
