"""Unit tests for Forward Deployment Engineering (FDE) foundation and data models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packages.review.fde.models import (
    FdeEvidence,
    FdeMission,
    FdeStep,
    OperationCategory,
    PreflightFinding,
    PreflightReport,
    PreflightSeverity,
    PreflightStatus,
    Runbook,
    RunbookInstruction,
    StepDependency,
    StepRiskLevel,
    StepStatus,
)


def test_valid_mission_and_topological_ordering() -> None:
    step_db = FdeStep(
        id="db_migrate",
        description="Run database migrations",
        operation_category=OperationCategory.REVERSIBLE_MUTATION,
        risk_level=StepRiskLevel.MEDIUM,
        timeout_seconds=60.0,
        target_adapter="postgres",
    )
    step_redis = FdeStep(
        id="redis_warm",
        description="Warmup cache",
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
        target_adapter="system",
    )
    step_api = FdeStep(
        id="api_deploy",
        description="Start application container",
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        dependencies=[
            StepDependency(step_id="db_migrate"),
            StepDependency(step_id="redis_warm"),
        ],
        risk_level=StepRiskLevel.HIGH,
        timeout_seconds=45.0,
        target_adapter="docker",
    )
    step_verify = FdeStep(
        id="health_verify",
        description="Verify service health endpoint",
        operation_category=OperationCategory.READ_ONLY,
        dependencies=[StepDependency(step_id="api_deploy")],
        risk_level=StepRiskLevel.LOW,
        target_adapter="http",
    )

    # Mission created in arbitrary order
    mission = FdeMission(
        name="Deploy Core Service",
        objective="Deploy database and start container with health check",
        steps=[step_verify, step_api, step_redis, step_db],
    )

    assert mission.schema_version == "1.0.0"
    assert mission.created_at.tzinfo == UTC

    # Verify topological ordering
    ordered = mission.get_topological_steps()
    ordered_ids = [s.id for s in ordered]

    # db_migrate and redis_warm must precede api_deploy
    assert ordered_ids.index("db_migrate") < ordered_ids.index("api_deploy")
    assert ordered_ids.index("redis_warm") < ordered_ids.index("api_deploy")
    # api_deploy must precede health_verify
    assert ordered_ids.index("api_deploy") < ordered_ids.index("health_verify")


def test_duplicate_step_id_rejected() -> None:
    s1 = FdeStep(id="step_a", description="First")
    s2 = FdeStep(id="step_a", description="Duplicate")

    with pytest.raises(ValidationError, match="Duplicate step identifier"):
        FdeMission(name="Test", objective="Test", steps=[s1, s2])


def test_self_dependency_rejected() -> None:
    step = FdeStep(
        id="step_a",
        description="Self dependent",
        dependencies=[StepDependency(step_id="step_a")],
    )
    with pytest.raises(ValidationError, match="cannot depend on itself"):
        FdeMission(name="Test", objective="Test", steps=[step])


def test_missing_dependency_target_rejected() -> None:
    step = FdeStep(
        id="step_a",
        description="Missing dep",
        dependencies=[StepDependency(step_id="non_existent_step")],
    )
    with pytest.raises(ValidationError, match="references non-existent dependency"):
        FdeMission(name="Test", objective="Test", steps=[step])


def test_duplicate_dependency_rejected() -> None:
    s1 = FdeStep(id="step_1", description="Dep target")
    s2 = FdeStep(
        id="step_2",
        description="Has dup deps",
        dependencies=[
            StepDependency(step_id="step_1"),
            StepDependency(step_id="step_1"),
        ],
    )
    with pytest.raises(ValidationError, match="contains duplicate dependency"):
        FdeMission(name="Test", objective="Test", steps=[s1, s2])


def test_cyclic_dependency_rejected() -> None:
    # 2-step cycle: A -> B -> A
    sa = FdeStep(id="step_a", description="A", dependencies=[StepDependency(step_id="step_b")])
    sb = FdeStep(id="step_b", description="B", dependencies=[StepDependency(step_id="step_a")])

    with pytest.raises(ValidationError, match="Cyclic dependency detected"):
        FdeMission(name="Cycle Test", objective="Cycle", steps=[sa, sb])

    # 3-step cycle: A -> B -> C -> A
    s1 = FdeStep(id="s1", description="S1", dependencies=[StepDependency(step_id="s3")])
    s2 = FdeStep(id="s2", description="S2", dependencies=[StepDependency(step_id="s1")])
    s3 = FdeStep(id="s3", description="S3", dependencies=[StepDependency(step_id="s2")])

    with pytest.raises(ValidationError, match="Cyclic dependency detected"):
        FdeMission(name="Cycle 3 Test", objective="Cycle", steps=[s1, s2, s3])


def test_step_timeout_bounds_enforced() -> None:
    # Minimum is 0.5s
    with pytest.raises(ValidationError):
        FdeStep(id="s", description="s", timeout_seconds=0.1)

    # Maximum is 3600.0s (1 hour)
    with pytest.raises(ValidationError):
        FdeStep(id="s", description="s", timeout_seconds=7200.0)

    # Valid bounds
    step = FdeStep(id="s", description="s", timeout_seconds=120.0)
    assert step.timeout_seconds == 120.0


def test_preflight_report_auto_counts_and_blocking_status() -> None:
    f_crit = PreflightFinding(
        rule_id="PRE-NET-001",
        severity=PreflightSeverity.CRITICAL,
        category="NETWORK",
        title="Port Conflict",
        message="Port 5432 is already bound by another process.",
        blocking=True,
    )
    f_warn = PreflightFinding(
        rule_id="PRE-CFG-002",
        severity=PreflightSeverity.WARNING,
        category="CONFIG",
        title="Optional Log Level Unset",
        message="LOG_LEVEL is not set, defaulting to INFO.",
        blocking=False,
    )

    report = PreflightReport(
        status=PreflightStatus.READY,  # Initially marked READY, but has blocking CRITICAL
        findings=[f_crit, f_warn],
    )

    # Status must automatically escalate to BLOCKED due to blocking CRITICAL finding
    assert report.status == PreflightStatus.BLOCKED
    assert report.severity_counts["CRITICAL"] == 1
    assert report.severity_counts["WARNING"] == 1
    assert report.severity_counts["ERROR"] == 0


def test_runbook_instructions_and_evidence() -> None:
    instruction = RunbookInstruction(
        step_number=1,
        step_id="start_pg",
        title="Start PostgreSQL Container",
        command_or_action="docker compose up -d postgres",
        expected_output="Started",
        verification_check="pg_isready -h localhost",
        rollback_action="docker compose stop postgres",
    )
    runbook = Runbook(
        deployment_context={"env": "staging"},
        prerequisites=["Docker installed", "Compose v2"],
        ordered_instructions=[instruction],
        verification_steps=["Run smoke tests"],
        rollback_guidance=["Restore database snapshot"],
    )
    assert len(runbook.ordered_instructions) == 1
    assert runbook.ordered_instructions[0].step_id == "start_pg"

    evidence = FdeEvidence(
        mission_id="m-123",
        step_id="start_pg",
        adapter_name="docker",
        operation="compose_up",
        status=StepStatus.SUCCEEDED,
        sanitized_output="Container started successfully",
        postcondition_results={"pg_isready": True},
    )
    assert evidence.status == StepStatus.SUCCEEDED
    assert evidence.postcondition_results["pg_isready"] is True


def test_secret_redaction_in_json_output() -> None:
    secret_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    step = FdeStep(
        id="auth_step",
        description="Authenticate",
        parameters={"token": secret_token},
    )
    mission = FdeMission(
        name="Secret Mission",
        objective="Test token redaction",
        steps=[step],
        policy_context={"api_key": "sk-proj-supersecret1234567890"},
    )

    json_str = mission.to_json()
    assert secret_token not in json_str
    assert "[REDACTED_TOKEN]" in json_str or "[REDACTED_API_KEY]" in json_str or "[REDACTED" in json_str


def test_deterministic_round_trip_serialization() -> None:
    step = FdeStep(
        id="build_step",
        description="Build package",
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
        timeout_seconds=30.0,
    )
    mission = FdeMission(
        id="mission-fixed-id",
        name="Deterministic Mission",
        objective="Round trip verification",
        steps=[step],
        created_at=datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC),
    )

    json_dump = mission.model_dump_json()
    deserialized = FdeMission.model_validate_json(json_dump)

    assert deserialized.id == mission.id
    assert deserialized.name == mission.name
    assert deserialized.created_at == mission.created_at
    assert len(deserialized.steps) == 1
    assert deserialized.steps[0].id == "build_step"
