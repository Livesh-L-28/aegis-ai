"""Domain models and contracts for LogicFalcon Forward Deployment Engineering (FDE)."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from packages.review.adapters.ast_security import redact_secrets_in_text


class OperationCategory(StrEnum):
    """Classification of FDE operations according to their mutation profile and risk."""

    READ_ONLY = "READ_ONLY"
    REVERSIBLE_MUTATION = "REVERSIBLE_MUTATION"
    CONSEQUENTIAL_MUTATION = "CONSEQUENTIAL_MUTATION"
    DESTRUCTIVE = "DESTRUCTIVE"


class StepRiskLevel(StrEnum):
    """Inherent risk level of an engineering deployment step."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StepStatus(StrEnum):
    """Lifecycle execution status of a mission step."""

    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class PreflightStatus(StrEnum):
    """Overall environment readiness state assessed by preflight discovery."""

    READY = "READY"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class PreflightSeverity(StrEnum):
    """Severity of a discovered preflight issue or defect."""

    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class StepDependency(BaseModel):
    """Explicit dependency requirement for a mission step."""

    step_id: str
    required_status: StepStatus = StepStatus.SUCCEEDED

    @field_validator("step_id")
    @classmethod
    def validate_step_id(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("step_id cannot be empty or whitespace.")
        return s


class FdeStep(BaseModel):
    """Individual declarative step within a Forward Deployment Engineering mission."""

    id: str
    name: str = ""
    description: str
    operation_category: OperationCategory = OperationCategory.READ_ONLY
    dependencies: list[StepDependency] = Field(default_factory=list)
    risk_level: StepRiskLevel = StepRiskLevel.LOW
    timeout_seconds: float = Field(default=30.0, ge=0.5, le=3600.0)
    preconditions: list[str] = Field(default_factory=list)
    expected_postconditions: list[str] = Field(default_factory=list)
    idempotent: bool = True
    requires_approval: bool = False
    target_adapter: str = "system"
    adapter_id: str = "system"
    operation: str = ""
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("step id cannot be empty or whitespace.")
        return s


class FdeMission(BaseModel):
    """Typed, dependency-aware deployment workflow composed of ordered, verified steps."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    objective: str
    steps: list[FdeStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "1.0.0"
    policy_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def validate_timezone(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("created_at must have explicit timezone information (UTC).")
        return v

    def _validate_dag_integrity(self) -> "FdeMission":
        # 1. Enforce unique step IDs
        seen_ids: set[str] = set()
        for step in self.steps:
            if step.id in seen_ids:
                raise ValueError(f"Duplicate step identifier detected: '{step.id}'")
            seen_ids.add(step.id)

        # 2. Check dependencies (existence, self-dependency, uniqueness)
        adj: dict[str, list[str]] = {}
        for step in self.steps:
            step_deps: set[str] = set()
            dep_list: list[str] = []
            for dep in step.dependencies:
                if dep.step_id == step.id:
                    raise ValueError(f"Step '{step.id}' cannot depend on itself.")
                if dep.step_id not in seen_ids:
                    raise ValueError(
                        f"Step '{step.id}' references non-existent dependency: '{dep.step_id}'"
                    )
                if dep.step_id in step_deps:
                    raise ValueError(
                        f"Step '{step.id}' contains duplicate dependency on '{dep.step_id}'"
                    )
                step_deps.add(dep.step_id)
                dep_list.append(dep.step_id)
            adj[step.id] = dep_list

        # 3. Detect cycles via DFS (white=0, gray=1, black=2)
        color: dict[str, int] = dict.fromkeys(seen_ids, 0)
        path: list[str] = []

        def dfs(node: str) -> None:
            color[node] = 1  # visiting
            path.append(node)

            for neighbor in adj.get(node, []):
                if color[neighbor] == 1:
                    # Cycle detected: extract cycle path
                    cycle_start = path.index(neighbor)
                    cycle_nodes = [*path[cycle_start:], neighbor]
                    raise ValueError(
                        f"Cyclic dependency detected in mission steps: {' -> '.join(cycle_nodes)}"
                    )
                elif color[neighbor] == 0:
                    dfs(neighbor)

            path.pop()
            color[node] = 2  # visited

        for s_id in seen_ids:
            if color[s_id] == 0:
                dfs(s_id)

        return self

    @model_validator(mode="after")
    def validate_workflow_graph(self) -> "FdeMission":
        return self._validate_dag_integrity()

    def validate_dag(self) -> "FdeMission":
        """Explicitly re-validates the workflow DAG."""
        return self._validate_dag_integrity()

    def get_topological_steps(self) -> list[FdeStep]:
        """Returns steps ordered such that each step appears only after all its dependencies."""
        step_map = {step.id: step for step in self.steps}
        in_degree: dict[str, int] = {step.id: 0 for step in self.steps}
        dependents: dict[str, list[str]] = {step.id: [] for step in self.steps}

        for step in self.steps:
            in_degree[step.id] = len(step.dependencies)
            for dep in step.dependencies:
                dependents[dep.step_id].append(step.id)

        queue = [s_id for s_id, deg in sorted(in_degree.items()) if deg == 0]
        ordered: list[FdeStep] = []

        while queue:
            curr = queue.pop(0)
            ordered.append(step_map[curr])
            for nxt in sorted(dependents[curr]):
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    queue.append(nxt)

        if len(ordered) != len(self.steps):
            raise ValueError("Dependency resolution failed; possible cyclic dependency.")
        return ordered

    def get_execution_order(self) -> list[list[str]]:
        """Returns steps grouped into dependency-independent topological execution levels."""
        in_degree: dict[str, int] = {step.id: len(step.dependencies) for step in self.steps}
        dependents: dict[str, list[str]] = {step.id: [] for step in self.steps}
        for step in self.steps:
            for dep in step.dependencies:
                dependents[dep.step_id].append(step.id)

        levels: list[list[str]] = []
        current_level = [s_id for s_id, deg in sorted(in_degree.items()) if deg == 0]

        while current_level:
            levels.append(current_level)
            next_level: list[str] = []
            for curr in current_level:
                for nxt in dependents[curr]:
                    in_degree[nxt] -= 1
                    if in_degree[nxt] == 0:
                        next_level.append(nxt)
            current_level = sorted(next_level)

        return levels

    def to_json(self, indent: int = 2) -> str:
        """Serializes mission to secret-redacted, schema-stable JSON."""
        return redact_secrets_in_text(self.model_dump_json(indent=indent))


class DeploymentRequirement(BaseModel):
    """Declarative prerequisite discovered from project architecture and configuration."""

    name: str
    requirement_type: str  # e.g., 'RUNTIME', 'PORT', 'ENV_VAR', 'DATABASE', 'CONTAINER', 'NETWORK'
    target: str
    is_required: bool = True
    source_file: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class DeploymentInventory(BaseModel):
    """Static and structural deployment inventory extracted from repository assets."""

    frameworks: list[str] = Field(default_factory=list)
    declared_ports: list[int] = Field(default_factory=list)
    required_env_vars: list[str] = Field(default_factory=list)
    optional_env_vars: list[str] = Field(default_factory=list)
    database_types: list[str] = Field(default_factory=list)
    container_definitions: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    runtime_versions: dict[str, str] = Field(default_factory=dict)
    requirements: list[DeploymentRequirement] = Field(default_factory=list)


class PreflightFinding(BaseModel):
    """Specific environmental or dependency finding identified during preflight discovery."""

    rule_id: str
    severity: PreflightSeverity
    category: str
    title: str
    message: str
    remediation: str | None = None
    blocking: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class PreflightReport(BaseModel):
    """Complete preflight discovery evaluation of deployment environment readiness."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    status: PreflightStatus
    findings: list[PreflightFinding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    observed_evidence: list[str] = Field(default_factory=list)
    inferred_risks: list[str] = Field(default_factory=list)
    recommended_remediations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "1.0.0"

    @model_validator(mode="after")
    def compute_counts_and_validate(self) -> "PreflightReport":
        counts: dict[str, int] = {sev.value: 0 for sev in PreflightSeverity}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        self.severity_counts = counts

        has_blocking_critical = any(
            f.severity == PreflightSeverity.CRITICAL and f.blocking for f in self.findings
        )
        if has_blocking_critical and self.status == PreflightStatus.READY:
            self.status = PreflightStatus.BLOCKED

        return self

    def to_json(self, indent: int = 2) -> str:
        """Serializes preflight report to secret-redacted JSON."""
        return redact_secrets_in_text(self.model_dump_json(indent=indent))


class RunbookInstruction(BaseModel):
    """Single actionable operator instruction within an operational runbook."""

    step_number: int
    step_id: str
    title: str
    command_or_action: str
    expected_output: str | None = None
    verification_check: str | None = None
    rollback_action: str | None = None
    is_automated: bool = True


class Runbook(BaseModel):
    """Operator runbook providing human-readable procedures and handover guidance."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    deployment_context: dict[str, Any] = Field(default_factory=dict)
    prerequisites: list[str] = Field(default_factory=list)
    ordered_instructions: list[RunbookInstruction] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    rollback_guidance: list[str] = Field(default_factory=list)
    unresolved_risks: list[str] = Field(default_factory=list)
    handover_notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "1.0.0"

    def to_json(self, indent: int = 2) -> str:
        """Serializes runbook to secret-redacted JSON."""
        return redact_secrets_in_text(self.model_dump_json(indent=indent))


class FdeEvidence(BaseModel):
    """Cryptographically timestamped, secret-redacted execution record for a deployment step."""

    mission_id: str
    step_id: str
    adapter_name: str
    operation: str
    status: StepStatus
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sanitized_output: str = ""
    postcondition_results: dict[str, bool] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
