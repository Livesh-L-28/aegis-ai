"""Tests for LogicFalcon FDE Postcondition Verifier, Diagnostics, Checkpoints, and Runbook Generator."""

import socket
from datetime import UTC, datetime
from pathlib import Path

from packages.review.fde.adapters import AdapterExecutionResult
from packages.review.fde.models import (
    DeploymentInventory,
    FdeEvidence,
    FdeMission,
    FdeStep,
    StepStatus,
)
from packages.review.fde.orchestration import (
    MissionExecutionReport,
    MissionStatus,
    StepExecutionSummary,
)
from packages.review.fde.verification import (
    FailureDiagnoser,
    FdeCheckpointStore,
    PostconditionVerifier,
    RunbookGenerator,
    VerificationOutcome,
)

# ==============================================================================
# 1. PostconditionVerifier Tests
# ==============================================================================


def test_postcondition_http_status() -> None:
    verifier = PostconditionVerifier()

    res_ok = AdapterExecutionResult(success=True, operation="get", output={"status_code": 200})
    ver_ok = verifier.verify_http_status(res_ok, expected_status=200)
    assert ver_ok.outcome == VerificationOutcome.VERIFIED_SUCCESS

    res_fail = AdapterExecutionResult(success=False, operation="get", output={"status_code": 500})
    ver_fail = verifier.verify_http_status(res_fail, expected_status=200)
    assert ver_fail.outcome == VerificationOutcome.FAILED

    res_inconclusive = AdapterExecutionResult(success=False, operation="get", output="bad_output")
    ver_inc = verifier.verify_http_status(res_inconclusive, expected_status=200)
    assert ver_inc.outcome == VerificationOutcome.INCONCLUSIVE


def test_postcondition_json_body_contains() -> None:
    verifier = PostconditionVerifier()

    res_ok = AdapterExecutionResult(
        success=True,
        operation="get",
        output={"body": '{"status": "ready", "version": "1.2.3"}'},
    )
    ver_key = verifier.verify_json_body_contains(res_ok, key="status")
    assert ver_key.outcome == VerificationOutcome.VERIFIED_SUCCESS

    ver_val = verifier.verify_json_body_contains(res_ok, key="version", expected_value="1.2.3")
    assert ver_val.outcome == VerificationOutcome.VERIFIED_SUCCESS

    ver_mismatch = verifier.verify_json_body_contains(res_ok, key="version", expected_value="2.0.0")
    assert ver_mismatch.outcome == VerificationOutcome.FAILED

    ver_missing = verifier.verify_json_body_contains(res_ok, key="nonexistent")
    assert ver_missing.outcome == VerificationOutcome.FAILED


def test_postcondition_tcp_port_open() -> None:
    verifier = PostconditionVerifier()

    # Open a real local socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    open_port = srv.getsockname()[1]

    try:
        ver_open = verifier.verify_tcp_port_open("127.0.0.1", open_port, timeout=1.0)
        assert ver_open.outcome == VerificationOutcome.VERIFIED_SUCCESS
    finally:
        srv.close()

    # Closed port
    ver_closed = verifier.verify_tcp_port_open("127.0.0.1", open_port, timeout=0.5)
    assert ver_closed.outcome == VerificationOutcome.FAILED


# ==============================================================================
# 2. FailureDiagnoser Tests
# ==============================================================================


def test_failure_diagnoser_connection_and_timeout() -> None:
    diagnoser = FailureDiagnoser()

    failed_steps = [
        StepExecutionSummary(
            step_id="step-conn",
            status=StepStatus.FAILED,
            operation="http_get",
            target="http://localhost:8000/health",
            success=False,
            error="Connect error: Connection refused to 127.0.0.1:8000",
        ),
        StepExecutionSummary(
            step_id="step-timeout",
            status=StepStatus.FAILED,
            operation="db_query",
            target="postgres",
            success=False,
            execution_time_seconds=5.0,
            error="Database operation timed out after 5.0s.",
        ),
    ]

    hypotheses = diagnoser.diagnose(failed_steps)
    assert len(hypotheses) == 2

    # Hypothesis 1: Connection refused
    h1 = hypotheses[0]
    assert "Service Unreachable" in h1.title
    assert h1.confidence >= 0.9
    assert h1.is_speculative is False

    # Hypothesis 2: Timeout
    h2 = hypotheses[1]
    assert "Operation Timeout" in h2.title
    assert h2.confidence >= 0.8
    assert h2.is_speculative is False


def test_failure_diagnoser_policy_and_generic_speculation() -> None:
    diagnoser = FailureDiagnoser()

    failed_steps = [
        StepExecutionSummary(
            step_id="step-policy",
            status=StepStatus.FAILED,
            operation="http_post",
            target="http://deploy.internal",
            success=False,
            error="Policy Gateway Blocked: requires explicit human approval token",
        ),
        StepExecutionSummary(
            step_id="step-unknown",
            status=StepStatus.FAILED,
            operation="unknown_op",
            target="system",
            success=False,
            error="Unanticipated runtime internal failure code 99",
        ),
    ]

    hypotheses = diagnoser.diagnose(failed_steps)
    assert len(hypotheses) == 2

    # Policy block is 100% confident
    assert hypotheses[0].confidence == 1.0
    assert hypotheses[0].is_speculative is False

    # Generic error is marked speculative with lower confidence
    assert hypotheses[1].is_speculative is True
    assert hypotheses[1].confidence <= 0.7


# ==============================================================================
# 3. FdeCheckpointStore Tests
# ==============================================================================


def test_checkpoint_store_atomic_save_load_and_redaction(tmp_path: Path) -> None:
    store = FdeCheckpointStore(storage_dir=tmp_path / "checkpoints")

    evidence = FdeEvidence(
        mission_id="mission-42",
        step_id="step-1",
        adapter_name="http",
        operation="http_get",
        status=StepStatus.SUCCEEDED,
        sanitized_output='{"token": "ghp_1234567890abcdef1234567890abcdef12"}',
    )

    report = MissionExecutionReport(
        mission_id="mission-42",
        status=MissionStatus.SUCCEEDED,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        total_steps=1,
        succeeded_steps=1,
        failed_steps=0,
        blocked_steps=0,
        cancelled_steps=0,
        step_summaries=[
            StepExecutionSummary(
                step_id="step-1",
                status=StepStatus.SUCCEEDED,
                operation="http_get",
                target="http://localhost:8000",
                success=True,
                evidence=evidence,
            )
        ],
        evidence_records=[evidence],
    )

    meta = {"api_key": "super_secret_api_key_1234567890abcdef"}
    saved_path = store.save_checkpoint(report, metadata=meta)
    assert saved_path.is_file()

    # Verify secret canary was redacted on disk
    file_content = saved_path.read_text(encoding="utf-8")
    assert "super_secret_api_key" not in file_content
    assert "ghp_1234567890" not in file_content
    assert "[REDACTED" in file_content

    # Load checkpoint
    loaded = store.load_checkpoint("mission-42")
    assert loaded is not None
    assert loaded["mission"]["mission_id"] == "mission-42"
    assert loaded["mission"]["status"] == "SUCCEEDED"

    # List checkpoints
    checkpoints = store.list_checkpoints()
    assert checkpoints == ["mission-42"]


# ==============================================================================
# 4. RunbookGenerator Tests
# ==============================================================================


def test_runbook_generator_markdown_and_redaction() -> None:
    generator = RunbookGenerator()

    step1 = FdeStep(
        id="step-1",
        name="Probe Service",
        description="Check endpoint",
        target_adapter="http",
        operation="http_health_check",
        target="http://localhost:8000/health",
        requires_approval=False,
    )
    step2 = FdeStep(
        id="step-2",
        name="Deploy Container",
        description="Deploy container with secret token ghp_1234567890abcdef1234567890abcdef12",
        target_adapter="docker",
        operation="start_container",
        target="api-container",
        requires_approval=True,
    )

    mission = FdeMission(
        name="Production Launch",
        objective="Verify and launch container service",
        steps=[step1, step2],
    )

    inventory = DeploymentInventory(
        frameworks=["FastAPI"],
        declared_ports=[8000],
        runtime_versions={"python": ">=3.12"},
    )

    # 1. Generate typed Runbook
    runbook = generator.generate_runbook(mission, inventory)
    assert len(runbook.ordered_instructions) == 2
    assert runbook.ordered_instructions[0].is_automated is True
    assert runbook.ordered_instructions[1].is_automated is False

    # 2. Render Markdown and verify secret canary redaction
    md = generator.generate_markdown(mission, inventory)
    assert "# Operational Runbook: Production Launch" in md
    assert "Python Runtime: >=3.12" in md
    assert "Requires Approval" in md
    assert "ghp_1234567890" not in md
    assert "[REDACTED" in md
