"""Domain models and schemas for LogicFalcon Phase 11 Historical Intelligence."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SnapshotSchemaVersion:
    CURRENT = "1.0"


class GitState(StrEnum):
    CLEAN = "clean"
    STAGED = "staged"
    WORKING_TREE = "working_tree"
    UNKNOWN = "unknown"


class FindingLifecycleState(StrEnum):
    """Lifecycle classification of a finding across revisions."""

    NEW = "NEW"              # Newly observed in current revision; absent in prior baseline
    UNCHANGED = "UNCHANGED"  # Present in both prior and current revisions with identical signature
    RESOLVED = "RESOLVED"    # Present in prior revision, verified absent in current revision
    REOPENED = "REOPENED"    # Previously observed, resolved, and reintroduced in current revision
    CHANGED = "CHANGED"      # Present in both, but severity, symbol, or message modified
    UNCERTAIN = "UNCERTAIN"  # Missing from current revision because file was skipped, unparsed, or analyzer disabled


class TrendDirection(StrEnum):
    """Directional trajectory of engineering health indicators over time."""

    IMPROVING = "IMPROVING"
    DETERIORATING = "DETERIORATING"
    STABLE = "STABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class PolicyMode(StrEnum):
    """Enforcement severity for historical engineering policy gates."""

    INFORMATIONAL = "INFORMATIONAL"
    WARNING = "WARNING"
    BLOCKING = "BLOCKING"


class SnapshotMetadata(BaseModel):
    """Provenance and context describing an analysis snapshot."""

    schema_version: str = SnapshotSchemaVersion.CURRENT
    logicfalcon_version: str = "0.1.2"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    repo_name: str = ""
    repo_path_hash: str = ""  # SHA-256 hash of absolute path for privacy
    revision: str | None = None
    git_state: GitState = GitState.UNKNOWN
    analyzer_versions: dict[str, str] = Field(default_factory=dict)
    enabled_analyzers: list[str] = Field(default_factory=list)
    config_fingerprint: str = ""
    discovered_files: int = 0
    parsed_files: int = 0
    skipped_files: int = 0
    scan_coverage: float = 1.0  # parsed / max(1, discovered)
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SnapshotFinding(BaseModel):
    """Normalized finding record persisted within a snapshot."""

    fingerprint: str  # 16-hex stable deduplication hash
    rule_id: str
    category: str
    severity: str  # "INFO", "WARNING", "ERROR", "CRITICAL"
    file_path: str  # repository-relative path
    start_line: int
    end_line: int | None = None
    symbol_name: str | None = None
    title: str = ""
    message: str = ""
    evidence_snippet: str = ""  # strictly redacted
    confidence: float = 1.0
    resolution_state: FindingLifecycleState = FindingLifecycleState.NEW
    first_seen_snapshot_id: str | None = None
    last_seen_snapshot_id: str | None = None
    first_seen_rev: str | None = None
    last_seen_rev: str | None = None


class RepositoryMetrics(BaseModel):
    """Normalized repository engineering metrics captured at snapshot time."""

    file_count: int = 0
    symbol_count: int = 0
    total_lines_of_code: int = 0
    graph_nodes: int = 0
    graph_edges: int = 0
    scc_count: int = 0
    cycle_count: int = 0
    boundary_violations_count: int = 0
    avg_instability: float = 0.0
    hotspot_count: int = 0
    health_score: float = 100.0
    api_route_count: int = 0
    data_model_count: int = 0
    entry_point_count: int = 0
    tech_debt_points: float = 0.0
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    category_distribution: dict[str, int] = Field(default_factory=dict)


class RepositorySnapshot(BaseModel):
    """Complete historical snapshot representing repository health at a specific revision."""

    id: UUID = Field(default_factory=uuid4)
    metadata: SnapshotMetadata
    metrics: RepositoryMetrics
    findings: list[SnapshotFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class SnapshotSummary(BaseModel):
    """Compact summary projection used for history listing and querying."""

    id: UUID
    created_at: datetime
    repo_name: str
    revision: str | None = None
    git_state: str = "unknown"
    file_count: int = 0
    total_findings: int = 0
    health_score: float = 100.0
    tech_debt_points: float = 0.0


class FindingLifecycleTransition(BaseModel):
    """Transition detail for a single finding between two snapshots."""

    fingerprint: str
    rule_id: str
    file_path: str
    start_line: int
    severity: str
    previous_state: FindingLifecycleState | None = None
    current_state: FindingLifecycleState
    transition_reason: str
    is_confirmed: bool = True


class SnapshotComparison(BaseModel):
    """Deterministic comparative analysis between two repository snapshots."""

    id: UUID = Field(default_factory=uuid4)
    from_snapshot_id: str
    to_snapshot_id: str
    from_revision: str | None = None
    to_revision: str | None = None
    from_timestamp: datetime
    to_timestamp: datetime
    is_comparable: bool = True
    comparability_notes: list[str] = Field(default_factory=list)
    new_findings: list[SnapshotFinding] = Field(default_factory=list)
    resolved_findings: list[SnapshotFinding] = Field(default_factory=list)
    persistent_findings: list[SnapshotFinding] = Field(default_factory=list)
    reopened_findings: list[SnapshotFinding] = Field(default_factory=list)
    changed_findings: list[SnapshotFinding] = Field(default_factory=list)
    uncertain_findings: list[SnapshotFinding] = Field(default_factory=list)
    metric_deltas: dict[str, float] = Field(default_factory=dict)
    health_score_delta: float = 0.0
    tech_debt_delta: float = 0.0
    detected_regressions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class TrendPoint(BaseModel):
    """Single time-series observation in repository health history."""

    snapshot_id: str
    timestamp: datetime
    revision: str | None = None
    health_score: float = 100.0
    tech_debt_points: float = 0.0
    total_findings: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    cycle_count: int = 0
    boundary_violations_count: int = 0
    file_count: int = 0


class EngineeringTrendReport(BaseModel):
    """Aggregated trend analysis across a sequence of historical snapshots."""

    repository_name: str
    sample_count: int
    time_span_days: float
    trend_points: list[TrendPoint] = Field(default_factory=list)
    health_direction: TrendDirection = TrendDirection.STABLE
    debt_direction: TrendDirection = TrendDirection.STABLE
    debt_velocity: float = 0.0  # points delta per day or per snapshot
    recurring_rule_ids: list[tuple[str, int]] = Field(default_factory=list)  # (rule_id, frequency)
    net_findings_delta: int = 0
    summary_commentary: list[str] = Field(default_factory=list)


class TechnicalDebtEstimate(BaseModel):
    """Explainable technical debt assessment computed from measured findings and modularity."""

    total_points: float
    severity_breakdown: dict[str, float] = Field(default_factory=dict)
    category_breakdown: dict[str, float] = Field(default_factory=dict)
    top_debt_files: list[tuple[str, float]] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class PolicyRule(BaseModel):
    """Configurable rule threshold for automated engineering health gates."""

    id: str
    name: str = ""
    description: str = ""
    condition: str  # e.g., "max_new_critical_findings", "max_new_high_findings", "max_new_cycles", etc.
    threshold: float
    mode: PolicyMode = PolicyMode.BLOCKING


class PolicyViolation(BaseModel):
    """Detailed record of an evaluated engineering policy violation."""

    rule_id: str
    condition: str
    actual_value: float
    threshold_value: float
    mode: PolicyMode
    message: str
    is_blocking: bool = False


class PolicyEvaluationResult(BaseModel):
    """Comprehensive evaluation outcome of configured engineering policy gates."""

    passed: bool = True
    is_blocking_failure: bool = False
    violations: list[PolicyViolation] = Field(default_factory=list)
    warnings: list[PolicyViolation] = Field(default_factory=list)
    rules_evaluated: int = 0
    suggested_exit_code: int = 0  # 0: PASS, 1: BLOCKING_FAIL, 2: CONFIG_ERROR
