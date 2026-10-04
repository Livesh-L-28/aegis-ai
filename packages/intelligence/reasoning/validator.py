"""Structured reasoning schemas and rigorous grounding & hallucination validation."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from packages.intelligence.evidence.models import EvidenceItem


class ReasoningStep(BaseModel):
    """Structured step in the diagnostic deduction."""

    type: str = Field(..., description="OBSERVED FACT | INFERRED RELATIONSHIP | CONCLUSION | UNCERTAINTY")
    statement: str = Field(...)
    evidence_id: UUID | None = Field(default=None, description="Citations to verified evidence ID, if applicable")


class StructuredReasoningOutput(BaseModel):
    """Canonical structured RCA returned by a ReasoningModelProvider."""

    summary: str = Field(..., description="High-level incident summary")
    root_cause: str = Field(..., description="Identified root cause or UNKNOWN")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model self-reported confidence score")
    affected_services: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)
    reasoning_steps: list[ReasoningStep] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GroundingValidationError(ValueError):
    """Raised when the reasoning model hallucinates non-existent evidence IDs or makes ungrounded claims."""
    pass


class GroundingValidator:
    """Validates that all evidence cited by the model strictly exists and calculates grounded confidence."""

    @staticmethod
    def validate_groundedness(
        output: StructuredReasoningOutput,
        valid_evidence: list[EvidenceItem],
    ) -> None:
        """Verifies every cited evidence ID exists in the provided evidence packet."""
        valid_id_set = {e.id for e in valid_evidence}

        # Check supporting evidence IDs
        for eid in output.supporting_evidence_ids:
            if eid not in valid_id_set:
                raise GroundingValidationError(
                    f"Model hallucinated non-existent supporting evidence ID: {eid}"
                )

        # Check contradicting evidence IDs
        for eid in output.contradicting_evidence_ids:
            if eid not in valid_id_set:
                raise GroundingValidationError(
                    f"Model hallucinated non-existent contradicting evidence ID: {eid}"
                )

        # Check step evidence citations
        for step in output.reasoning_steps:
            if step.evidence_id and step.evidence_id not in valid_id_set:
                raise GroundingValidationError(
                    f"Reasoning step '{step.type}' cited non-existent evidence ID: {step.evidence_id}"
                )

        # Check: If root cause is declared without any supporting evidence and is not UNKNOWN, reject
        if output.root_cause != "UNKNOWN" and not output.supporting_evidence_ids:
            raise GroundingValidationError(
                "Model declared root cause without citing any supporting evidence IDs."
            )

    @staticmethod
    def calculate_final_confidence(
        model_confidence: float,
        supporting_evidence: list[EvidenceItem],
        contradicting_evidence: list[EvidenceItem],
        is_unknown: bool,
    ) -> float:
        """Formula:

        Final Confidence =
            Model Confidence
            * Evidence Quality Multiplier
            * Grounding Multiplier
            - Contradiction Penalty
        """
        if is_unknown or not supporting_evidence:
            return round(min(0.3, model_confidence), 2)

        # Average relevance/confidence of supporting evidence
        avg_quality = sum(e.relevance_score for e in supporting_evidence) / len(supporting_evidence)

        # Contradiction penalty
        penalty = 0.25 * len(contradicting_evidence)

        raw = (model_confidence * 0.5) + (avg_quality * 0.5) - penalty
        return round(min(1.0, max(0.05, raw)), 2)
