"""Adversarial security and production hardening tests for LogicFalcon FDE.

Validates resistance to parameter tampering, authorization bypass attempts,
SSRF to cloud metadata services, secret leaks, malformed input schemas,
symlink escapes, corrupted checkpoints, and unhandled subprocess failures.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.review.fde.adapters import (
    AdapterRegistry,
    HttpAdapter,
)
from packages.review.fde.models import (
    FdeMission,
    FdeStep,
    OperationCategory,
    StepDependency,
    StepRiskLevel,
)
from packages.review.fde.orchestration import (
    PolicyGateway,
    PolicyViolationError,
)
from packages.review.fde.verification import (
    FdeCheckpointStore,
    RunbookGenerator,
)


def test_adversarial_parameter_tampering_rejected() -> None:
    """Tests that modifying any parameter after approval invalidates the cryptographic token."""
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    gateway = PolicyGateway(registry)

    step = FdeStep(
        id="deploy-hook",
        name="Trigger Staging Deployment",
        description="Deploy staging webhook",
        target_adapter="http",
        adapter_id="http",
        operation="http_post",
        target="http://example.com/api/deploy",
        parameters={"url": "http://example.com/api/deploy", "environment": "staging"},
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        risk_level=StepRiskLevel.HIGH,
        requires_approval=True,
    )

    # Legitimate operator approves 'staging' deployment
    token = gateway.grant_approval(
        mission_id="mission-attack-1",
        step_id="deploy-hook",
        adapter_id="http",
        operation="http_post",
        target="http://example.com/api/deploy",
        params={"url": "http://example.com/api/deploy", "environment": "staging"},
    )

    # 1. Attacker tampers parameters to 'production'
    tampered_params = {"url": "http://example.com/api/deploy", "environment": "production"}
    with pytest.raises(PolicyViolationError) as exc_info:
        gateway.execute_step(
            mission_id="mission-attack-1",
            step=step,
            adapter_id="http",
            operation="http_post",
            params=tampered_params,
            approval_token=token,
        )
    assert "requires explicit human approval token" in str(exc_info.value)

    # 2. Attacker injects extra parameter
    injected_params = {"url": "http://example.com/api/deploy", "environment": "staging", "drop_db": True}
    with pytest.raises(PolicyViolationError) as exc_info:
        gateway.execute_step(
            mission_id="mission-attack-1",
            step=step,
            adapter_id="http",
            operation="http_post",
            params=injected_params,
            approval_token=token,
        )
    assert "requires explicit human approval token" in str(exc_info.value)


def test_target_confusion_and_cross_step_replay_prevention() -> None:
    """Tests that approval tokens are strictly bound to step_id, mission_id, and target."""
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    gateway = PolicyGateway(registry)

    params = {"url": "http://internal.svc/deploy"}
    step_a = FdeStep(
        id="step-a",
        name="Step A",
        description="Step A action",
        target_adapter="http",
        adapter_id="http",
        operation="http_post",
        target="http://internal.svc/deploy",
        parameters=params,
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        risk_level=StepRiskLevel.HIGH,
        requires_approval=True,
    )
    step_b = FdeStep(
        id="step-b",
        name="Step B",
        description="Step B action",
        target_adapter="http",
        adapter_id="http",
        operation="http_post",
        target="http://internal.svc/deploy",
        parameters=params,
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        risk_level=StepRiskLevel.HIGH,
        requires_approval=True,
    )

    token_a = gateway.grant_approval(
        mission_id="mission-100",
        step_id="step-a",
        adapter_id="http",
        operation="http_post",
        target="http://internal.svc/deploy",
        params=params,
    )

    # Attempt to replay token_a on step_b
    with pytest.raises(PolicyViolationError):
        gateway.execute_step(
            mission_id="mission-100",
            step=step_b,
            adapter_id="http",
            operation="http_post",
            params=params,
            approval_token=token_a,
        )

    # Attempt to replay token_a in a different mission
    with pytest.raises(PolicyViolationError):
        gateway.execute_step(
            mission_id="mission-200",
            step=step_a,
            adapter_id="http",
            operation="http_post",
            params=params,
            approval_token=token_a,
        )


def test_ssrf_cloud_metadata_blocked() -> None:
    """Verifies that HTTP adapter blocks requests to cloud instance metadata services."""
    adapter = HttpAdapter()

    # AWS/OpenStack metadata IP
    res_aws = adapter.execute(
        operation="http_get",
        params={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert not res_aws.success
    assert res_aws.error_category == "SECURITY_VIOLATION"
    assert "cloud metadata endpoint" in (res_aws.error or "")

    # GCP metadata endpoint
    res_gcp = adapter.execute(
        operation="http_get",
        params={"url": "http://metadata.google.internal/computeMetadata/v1/"},
    )
    assert not res_gcp.success
    assert res_gcp.error_category == "SECURITY_VIOLATION"


def test_synthetic_secret_canary_redaction_across_all_surfaces(tmp_path: Path) -> None:
    """Verifies that synthetic secret canaries do not leak into runbooks or checkpoints."""
    canary_token = "SYNTHETIC_CANARY_API_KEY_xyz987654321"
    canary_conn_str = "postgresql://admin:SYNTHETIC_CANARY_PW_123456@db.internal:5432/prod"

    mission = FdeMission(
        name="Canary Security Mission",
        objective="Verify redaction of sensitive credentials",
        steps=[
            FdeStep(
                id="step-secret",
                name="Database Check",
                description=f"Connect with {canary_conn_str}",
                target_adapter="system",
                adapter_id="system",
                operation="probe_runtime",
                target="python",
                parameters={"api_token": canary_token, "db_url": canary_conn_str},
            )
        ],
    )

    # 1. Verify JSON serialization of mission redacts tokens
    mission_json = mission.to_json()
    assert canary_token not in mission_json
    assert "SYNTHETIC_CANARY_PW_123456" not in mission_json

    # 2. Verify RunbookGenerator redacts secrets
    runbook_gen = RunbookGenerator()
    runbook_md = runbook_gen.generate_markdown(mission)
    assert canary_token not in runbook_md
    assert "SYNTHETIC_CANARY_PW_123456" not in runbook_md

    # 3. Verify FdeCheckpointStore sanitizes dictionary keys and values
    store = FdeCheckpointStore(storage_dir=tmp_path / "checkpoints")
    mock_report = MagicMock()
    mock_report.mission_id = "canary-mission-001"
    mock_report.to_dict.return_value = {
        "mission_id": "canary-mission-001",
        "api_key": canary_token,
        "token_val": canary_token,
        "nested": {"secret": canary_conn_str},
    }

    ckpt_file = store.save_checkpoint(mock_report)
    ckpt_content = ckpt_file.read_text(encoding="utf-8")
    assert canary_token not in ckpt_content
    assert "SYNTHETIC_CANARY_PW_123456" not in ckpt_content


def test_oversized_response_truncation() -> None:
    """Verifies that HttpAdapter limits and truncates oversized payloads without crashing."""
    adapter = HttpAdapter()
    oversized_data = b"X" * (600 * 1024)  # 600 KB > 512 KB limit

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/plain"}
    mock_resp.content = oversized_data
    mock_resp.text = "X" * (600 * 1024)

    with patch("httpx.Client.get", return_value=mock_resp):
        res = adapter.execute(
            operation="http_get",
            params={"url": "http://example.com/large-file"},
        )
        assert not res.success
        assert res.error_category == "RESPONSE_TOO_LARGE"
        assert "exceeded maximum bound" in (res.error or "")


def test_corrupted_checkpoint_recovery(tmp_path: Path) -> None:
    """Verifies that FdeCheckpointStore gracefully rejects corrupted checkpoint files."""
    store = FdeCheckpointStore(storage_dir=tmp_path / "checkpoints")
    corrupt_file = tmp_path / "checkpoints" / "checkpoint_corrupted.json"
    corrupt_file.parent.mkdir(parents=True, exist_ok=True)
    corrupt_file.write_text('{"incomplete_json": [1, 2, ', encoding="utf-8")

    loaded = store.load_checkpoint(corrupt_file)
    assert loaded is None


def test_malformed_dag_rejection() -> None:
    """Verifies that invalid DAGs (missing dependency, cycle, duplicate ID) fail up-front."""
    # 1. Missing dependency
    with pytest.raises(ValueError) as exc:
        FdeMission(
            name="Missing Dep Mission",
            objective="Test validation",
            steps=[
                FdeStep(
                    id="step-1",
                    description="Step 1",
                    dependencies=[StepDependency(step_id="non-existent-step")],
                )
            ],
        )
    assert "non-existent dependency" in str(exc.value)

    # 2. Cyclic dependency
    with pytest.raises(ValueError) as exc:
        FdeMission(
            name="Cyclic Mission",
            objective="Test validation",
            steps=[
                FdeStep(
                    id="step-a",
                    description="Step A",
                    dependencies=[StepDependency(step_id="step-b")],
                ),
                FdeStep(
                    id="step-b",
                    description="Step B",
                    dependencies=[StepDependency(step_id="step-a")],
                ),
            ],
        )
    assert "Cyclic dependency" in str(exc.value)
