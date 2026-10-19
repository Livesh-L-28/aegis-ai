"""Structured schemas for validating LLM code review responses."""

from pydantic import BaseModel, Field

from packages.review.domain.models import FindingCategory, FindingSeverity


class AIReviewFindingItem(BaseModel):
    """A single finding proposed by the AI code review model."""

    file_path: str
    start_line: int
    end_line: int | None = None
    title: str
    description: str
    category: FindingCategory = FindingCategory.QUALITY
    severity: FindingSeverity = FindingSeverity.WARNING
    technical_evidence: str
    impact: str = ""
    remediation: str = ""
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    rule_id: str = "AI-REVIEW"
    symbol_name: str | None = None


class AIReviewResponse(BaseModel):
    """Structured response contract for AI review invocations."""

    summary: str
    findings: list[AIReviewFindingItem] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
