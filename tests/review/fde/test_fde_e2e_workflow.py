"""End-to-End Validation and Failure Scenario Tests for LogicFalcon FDE.

Demonstrates complete local workflow:
1. Static repository discovery & prerequisite extraction.
2. Bounded preflight environment probes.
3. Mission DAG planning with topological ordering.
4. Policy gateway evaluation and cryptographic approval tokens.
5. Multi-level orchestrated execution with evidence collection.
6. Postcondition outcome verification.
7. Failure injection, automated root-cause diagnosis, and recovery.
8. Operational runbook compilation and handover report generation.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.review.fde.adapters import (
    AdapterExecutionResult,
    AdapterRegistry,
    HttpAdapter,
    SystemAdapter,
)
from packages.review.fde.discovery import DeploymentDiscoveryEngine
from packages.review.fde.models import (
    FdeMission,
    FdeStep,
    OperationCategory,
    PreflightStatus,
    StepDependency,
    StepRiskLevel,
)
from packages.review.fde.orchestration import (
    MissionOrchestrator,
    MissionStatus,
    PolicyGateway,
)
from packages.review.fde.preflight import PreflightRunner
from packages.review.fde.verification import (
    FailureDiagnoser,
    FdeCheckpointStore,
    PostconditionVerifier,
    RunbookGenerator,
    VerificationOutcome,
)


@pytest.fixture
def isolated_fastapi_repo(tmp_path: Path) -> Path:
    """Creates a realistic, isolated sample FastAPI + PostgreSQL repository fixture."""
    repo = tmp_path / "sample_fastapi_service"
    repo.mkdir()

    # pyproject.toml
    (repo / "pyproject.toml").write_text(
        """[project]
name = "customer-api"
version = "1.0.0"
dependencies = [
    "fastapi>=0.111.0",
    "uvicorn>=0.30.0",
    "asyncpg>=0.29.0",
    "pydantic>=2.7.0"
]
""",
        encoding="utf-8",
    )

    # docker-compose.yml
    (repo / "docker-compose.yml").write_text(
        """version: '3.8'
services:
  web:
    image: customer-api:latest
    ports:
      - '8000:8000'
    environment:
      - DATABASE_URL=postgresql://postgres:secret@db:5432/customer_db
      - API_PORT=8000
  db:
    image: postgres:16-alpine
    ports:
      - '5432:5432'
    environment:
      - POSTGRES_DB=customer_db
""",
        encoding="utf-8",
    )

    # .env.example
    (repo / ".env.example").write_text(
        """DATABASE_URL=postgresql://localhost:5432/customer_db
API_PORT=8000
SECRET_KEY=template_secret_key_to_be_replaced
""",
        encoding="utf-8",
    )

    # Dockerfile
    (repo / "Dockerfile").write_text(
        """FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
""",
        encoding="utf-8",
    )

    return repo


def test_e2e_complete_deployment_readiness_lifecycle(isolated_fastapi_repo: Path, tmp_path: Path) -> None:
    """Demonstrates complete 8-stage end-to-end deployment engineering workflow."""
    # --------------------------------------------------------------------------
    # Stage 1: Static Repository & Architecture Discovery
    # --------------------------------------------------------------------------
    discovery_engine = DeploymentDiscoveryEngine(repo_root=isolated_fastapi_repo)
    inventory = discovery_engine.discover()

    assert "FastAPI" in inventory.frameworks
    assert 8000 in inventory.declared_ports
    assert "PostgreSQL" in inventory.database_types
    assert "DATABASE_URL" in inventory.required_env_vars
    assert len(inventory.container_definitions) >= 1

    # --------------------------------------------------------------------------
    # Stage 2: Live Environment Preflight Probes
    # --------------------------------------------------------------------------
    preflight_runner = PreflightRunner(
        repo_root=isolated_fastapi_repo,
        check_ports=True,
        check_env_vars=False,  # Isolated test env
        check_docker=False,
    )
    preflight_report = preflight_runner.run_preflight(inventory=inventory)
    assert preflight_report.status in (PreflightStatus.READY, PreflightStatus.BLOCKED)
    assert len(preflight_report.observed_evidence) >= 1

    # --------------------------------------------------------------------------
    # Stage 3: Mission DAG Planning & Topological Validation
    # --------------------------------------------------------------------------
    step_runtime = FdeStep(
        id="step-1-runtime",
        name="Probe Python Runtime",
        description="Verify active Python environment version >= 3.12",
        target_adapter="system",
        adapter_id="system",
        operation="probe_runtime",
        target="python",
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
    )
    step_port = FdeStep(
        id="step-2-port",
        name="Check Port 8000",
        description="Verify port 8000 availability",
        target_adapter="system",
        adapter_id="system",
        operation="probe_port",
        target="8000",
        parameters={"port": 8000},
        dependencies=[StepDependency(step_id="step-1-runtime")],
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
    )
    step_health = FdeStep(
        id="step-3-health",
        name="Verify Service Health Endpoint",
        description="Perform HTTP GET health check on service endpoint",
        target_adapter="http",
        adapter_id="http",
        operation="http_health_check",
        target="http://127.0.0.1:8000/health",
        parameters={"url": "http://127.0.0.1:8000/health"},
        dependencies=[StepDependency(step_id="step-2-port")],
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
    )

    mission = FdeMission(
        name="Customer API Deployment Verification",
        objective="Validate prerequisites and health endpoints for customer API service",
        steps=[step_runtime, step_port, step_health],
    )

    # Enforce DAG validation
    execution_levels = mission.get_execution_order()
    assert len(execution_levels) == 3
    assert execution_levels[0] == ["step-1-runtime"]
    assert execution_levels[1] == ["step-2-port"]
    assert execution_levels[2] == ["step-3-health"]

    # --------------------------------------------------------------------------
    # Stage 4: Capability Registry & Policy Gateway
    # --------------------------------------------------------------------------
    registry = AdapterRegistry()
    registry.register(SystemAdapter())
    registry.register(HttpAdapter())

    policy_gateway = PolicyGateway(registry)
    orchestrator = MissionOrchestrator(registry=registry, policy_gateway=policy_gateway)

    # --------------------------------------------------------------------------
    # Stage 5: Orchestrated Mission Execution with Evidence Logging
    # --------------------------------------------------------------------------
    mock_resp = MagicMock(status_code=200, content=b'{"status":"healthy"}', text='{"status":"healthy"}', headers={})
    with patch("httpx.Client.get", return_value=mock_resp):
        report = orchestrator.run_mission(mission)

    assert report.status == MissionStatus.SUCCEEDED
    assert report.total_steps == 3
    assert report.succeeded_steps == 3
    assert report.failed_steps == 0
    assert len(report.evidence_records) == 3

    # --------------------------------------------------------------------------
    # Stage 6: Postcondition Verification
    # --------------------------------------------------------------------------
    verifier = PostconditionVerifier()
    fake_adapter_result = AdapterExecutionResult(
        success=True,
        operation="http_health_check",
        output={"status_code": 200, "body": {"status": "healthy"}},
    )
    postcondition_res = verifier.verify_http_status(fake_adapter_result, expected_status=200)
    assert postcondition_res.outcome == VerificationOutcome.VERIFIED_SUCCESS
    assert postcondition_res.actual == 200

    # --------------------------------------------------------------------------
    # Stage 7: Atomic Checkpoint Persistence
    # --------------------------------------------------------------------------
    checkpoint_store = FdeCheckpointStore(storage_dir=tmp_path / "checkpoints")
    checkpoint_path = checkpoint_store.save_checkpoint(report)
    assert checkpoint_path.is_file()

    # Load and verify round-trip
    loaded_data = checkpoint_store.load_checkpoint(checkpoint_path)
    assert loaded_data is not None
    assert loaded_data["mission"]["mission_id"] == mission.id
    assert loaded_data["mission"]["status"] == "SUCCEEDED"

    # --------------------------------------------------------------------------
    # Stage 8: Operational Runbook & Handover Report Generation
    # --------------------------------------------------------------------------
    runbook_generator = RunbookGenerator()
    runbook = runbook_generator.generate_runbook(mission, inventory=inventory, execution_report=report)
    assert len(runbook.ordered_instructions) == 3

    markdown_runbook = runbook_generator.generate_markdown(mission, inventory=inventory, execution_report=report)
    assert "# Operational Runbook: Customer API Deployment Verification" in markdown_runbook
    assert "Probe Python Runtime" in markdown_runbook
    assert "Check Port 8000" in markdown_runbook


def test_e2e_failure_injection_cascade_and_diagnosis() -> None:
    """Verifies failure injection, cascade blocking of dependents, and automated diagnosis."""
    step_db = FdeStep(
        id="step-db-connect",
        name="Connect to PostgreSQL",
        description="Verify database connectivity",
        target_adapter="system",
        adapter_id="system",
        operation="probe_port",
        target="5432",
        parameters={"port": 5432},
        operation_category=OperationCategory.READ_ONLY,
    )
    step_migration = FdeStep(
        id="step-db-migrate",
        name="Run Database Migrations",
        description="Apply pending schema migrations",
        target_adapter="system",
        adapter_id="system",
        operation="check_env",
        target="MIGRATION_READY",
        dependencies=[StepDependency(step_id="step-db-connect")],
        operation_category=OperationCategory.READ_ONLY,
    )

    mission = FdeMission(
        name="Database Migration Mission",
        objective="Verify database readiness and apply migrations",
        steps=[step_db, step_migration],
    )

    registry = AdapterRegistry()
    registry.register(SystemAdapter())
    policy_gateway = PolicyGateway(registry)
    orchestrator = MissionOrchestrator(registry=registry, policy_gateway=policy_gateway)

    # Inject failure: port 5432 fails / throws error
    with patch("socket.socket.connect_ex", side_effect=OSError("Connection refused: 127.0.0.1:5432")):
        report = orchestrator.run_mission(mission)

    assert report.status == MissionStatus.FAILED
    assert report.failed_steps == 1
    assert report.blocked_steps == 1  # Dependent step must be cascaded to BLOCKED

    # Perform automated failure diagnosis
    diagnoser = FailureDiagnoser()
    failed_steps = [s for s in report.step_summaries if not s.success]
    hypotheses = diagnoser.diagnose(
        failed_steps=failed_steps,
        postcondition_results=[],
    )

    assert len(hypotheses) >= 1
    top_hypothesis = hypotheses[0]
    assert "Service Unreachable" in top_hypothesis.title or "Connection" in top_hypothesis.title or "Operational Failure" in top_hypothesis.title
    assert top_hypothesis.confidence >= 0.70
    assert len(top_hypothesis.recommended_action) > 0


def test_e2e_unauthorized_mutation_strictly_prevented() -> None:
    """Verifies that unauthorized mutating operations are blocked by PolicyGateway before execution."""
    step_mutate = FdeStep(
        id="step-restart-service",
        name="Restart Production Webhook",
        description="Trigger restart of customer API service",
        target_adapter="http",
        adapter_id="http",
        operation="http_post",
        target="http://127.0.0.1:8000/restart",
        parameters={"url": "http://127.0.0.1:8000/restart"},
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        risk_level=StepRiskLevel.HIGH,
        requires_approval=True,
    )

    mission = FdeMission(
        name="Service Restart Mission",
        objective="Attempt unauthorized restart",
        steps=[step_mutate],
    )

    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    policy_gateway = PolicyGateway(registry)
    orchestrator = MissionOrchestrator(registry=registry, policy_gateway=policy_gateway)

    # Execute without providing approval token
    report = orchestrator.run_mission(mission, approval_tokens={})
    assert report.status == MissionStatus.FAILED
    assert report.failed_steps == 1
    assert "requires explicit human approval token" in (report.step_summaries[0].error or "")


def test_e2e_postcondition_assertion_failure_handling() -> None:
    """Verifies that postcondition verification catches unverified health check outcomes."""
    verifier = PostconditionVerifier()

    mock_503_result = AdapterExecutionResult(
        success=False,
        operation="http_health_check",
        output={"status_code": 503, "body": {"status": "degraded"}},
    )
    res = verifier.verify_http_status(mock_503_result, expected_status=200)

    assert res.outcome == VerificationOutcome.FAILED
    assert res.actual == 503
    assert res.expected == 200
