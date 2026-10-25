"""Data models for LogicFalcon Unified Engineering Intelligence."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RecommendationPriority(StrEnum):
    """Priority level for engineering recommendations (distinct from finding severity)."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RecommendationCategory(StrEnum):
    """Domain category for unified recommendations."""

    SECURITY = "SECURITY"
    ARCHITECTURE = "ARCHITECTURE"
    RELIABILITY = "RELIABILITY"
    REGRESSION = "REGRESSION"
    TECHNICAL_DEBT = "TECHNICAL_DEBT"
    TEST_SELECTION = "TEST_SELECTION"


class UnifiedRecommendation(BaseModel):
    """Evidence-grounded engineering recommendation synthesized across analysis engines."""

    id: str
    priority: RecommendationPriority
    category: RecommendationCategory
    title: str
    rationale: str
    supporting_evidence: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    suggested_action: str
    suggested_tests: list[str] = Field(default_factory=list)
    acceptance_criteria: list[str] = Field(default_factory=list)
    confidence: float = 1.0  # 0.0 to 1.0 scale
    known_limitations: list[str] = Field(default_factory=list)


class UnifiedIntelligenceReport(BaseModel):
    """Complete, unified engineering intelligence report synthesizing all pillars."""

    id: UUID = Field(default_factory=uuid4)
    schema_version: str = "1.0.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    repository_path: str
    repository_id: str
    revision: str | None = None
    execution_time_seconds: float = 0.0

    # Summary metrics across engines
    review_findings_count: int = 0
    review_severity_counts: dict[str, int] = Field(default_factory=dict)
    architecture_score: float = 100.0
    circular_dependency_count: int = 0
    boundary_violations_count: int = 0
    total_files: int = 0
    total_routes: int = 0
    total_models: int = 0
    impact_risk_level: str = "LOW"
    impact_risk_score: float = 0.0
    recommended_tests_count: int = 0
    recommended_tests: list[str] = Field(default_factory=list)
    history_trend_direction: str = "STABLE"
    technical_debt_points: float = 0.0
    policy_passed: bool = True
    policy_violations_count: int = 0

    # Evidence-grounded recommendations
    recommendations: list[UnifiedRecommendation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
