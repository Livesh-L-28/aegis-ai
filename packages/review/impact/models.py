"""Domain models for LogicFalcon Change Impact Analysis and Predictive Test Selection."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from packages.review.domain.models import ChangedFile, ChangedSymbol


class ImpactType(StrEnum):
    """Categorization of dependency relationships between changed code and impacted entities."""

    DIRECT_DEPENDENCY = "DIRECT_DEPENDENCY"        # Directly imports changed file
    TRANSITIVE_DEPENDENCY = "TRANSITIVE_DEPENDENCY"  # Imports a dependent module (multi-hop)
    SYMBOL_REFERENCE = "SYMBOL_REFERENCE"          # Directly calls or references changed symbol
    API_ROUTE = "API_ROUTE"                        # API endpoint whose handler or schema is affected
    DATA_MODEL = "DATA_MODEL"                      # Domain/database model referenced or modified
    ENTRY_POINT = "ENTRY_POINT"                    # Application CLI script or main entry point
    TEST_ASSOCIATION = "TEST_ASSOCIATION"          # Test that exercises the affected code
    LAYER_CROSSING = "LAYER_CROSSING"              # Architectural boundary crossed
    HEURISTIC = "HEURISTIC"                        # Convention or loose filename match


class ConfidenceCategory(StrEnum):
    """Confidence level of static impact evidence."""

    HIGH = "HIGH"      # Explicit static import, symbol reference, or direct test import
    MEDIUM = "MEDIUM"  # Multi-hop transitive dependency or framework route mapping
    LOW = "LOW"        # Heuristic, naming convention, or unresolved dynamic edge


class ImpactRiskLevel(StrEnum):
    """Overall risk classification of a change set based on blast radius and criticality."""

    LOW = "LOW"            # Isolated change with small blast radius and complete test coverage
    MEDIUM = "MEDIUM"      # Moderate blast radius or cross-module dependencies
    HIGH = "HIGH"          # Wide blast radius, entry-point reachability, or architectural boundary crossings
    CRITICAL = "CRITICAL"  # High blast radius touching core models, auth/security components, or database migrations


class ImpactEvidence(BaseModel):
    """Concrete, verifiable evidence explaining an impact relationship."""

    source_entity: str
    target_entity: str
    relationship_type: ImpactType
    confidence: ConfidenceCategory = ConfidenceCategory.HIGH
    evidence_snippet: str = ""
    depth: int = 1
    shortest_path: list[str] = Field(default_factory=list)
    line_number: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ImpactedEntity(BaseModel):
    """A module, symbol, or component identified as potentially affected by a change."""

    file_path: str
    symbol_name: str | None = None
    component_name: str | None = None
    layer: str | None = None
    impact_type: ImpactType
    depth: int = 1
    shortest_path: list[str] = Field(default_factory=list)
    impact_score: float = 0.0
    impact_reasons: list[str] = Field(default_factory=list)
    evidence: list[ImpactEvidence] = Field(default_factory=list)
    associated_routes: list[dict[str, Any]] = Field(default_factory=list)
    associated_models: list[dict[str, Any]] = Field(default_factory=list)
    affected_entry_points: list[str] = Field(default_factory=list)
    relevant_findings: list[dict[str, Any]] = Field(default_factory=list)


class TestImpactCandidate(BaseModel):
    """A test recommended for execution based on static dependency evidence."""

    test_file: str
    test_symbol: str | None = None
    associated_target: str
    selection_reason: str
    confidence: ConfidenceCategory = ConfidenceCategory.HIGH
    relationship_type: ImpactType = ImpactType.TEST_ASSOCIATION
    evidence: ImpactEvidence | None = None


class ChangeSet(BaseModel):
    """Normalized representation of changes detected or supplied for impact analysis."""

    origin: str = "working_tree"  # 'working_tree', 'staged', 'git_revision', 'explicit_files'
    base_revision: str | None = None
    target_revision: str | None = None
    changed_files: list[ChangedFile] = Field(default_factory=list)
    changed_symbols: list[ChangedSymbol] = Field(default_factory=list)
    added_paths: list[str] = Field(default_factory=list)
    modified_paths: list[str] = Field(default_factory=list)
    deleted_paths: list[str] = Field(default_factory=list)
    renamed_paths: list[tuple[str, str]] = Field(default_factory=list)  # (old_path, new_path)
    unresolved_paths: list[str] = Field(default_factory=list)
    total_added_lines: int = 0
    total_deleted_lines: int = 0


class ImpactAnalysisLimitation(BaseModel):
    """Explicitly records gaps, heuristics, or unanalyzed constructs."""

    category: str
    file_path: str
    description: str


class ChangeImpactReport(BaseModel):
    """Comprehensive change-impact analysis report."""

    id: UUID = Field(default_factory=uuid4)
    repository_path: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    execution_time_seconds: float = 0.0
    change_set: ChangeSet
    impacted_entities: list[ImpactedEntity] = Field(default_factory=list)
    recommended_tests: list[TestImpactCandidate] = Field(default_factory=list)
    risk_level: ImpactRiskLevel = ImpactRiskLevel.LOW
    risk_score: float = 0.0  # 0.0 to 100.0
    risk_reasons: list[str] = Field(default_factory=list)
    limitations: list[ImpactAnalysisLimitation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
