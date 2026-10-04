"""Unit tests for AEGIS AI Reliability engine adapter and domain mappings."""

from uuid import uuid4

from packages.reliability.adapter import AIReliabilityPackageAdapter
from packages.reliability.domain import (
    ExecutionRecordDTO,
    ReliabilityStatus,
)


def test_reliability_adapter_health() -> None:
    """Verifies that the adapter detects the real installed aireliability package."""
    adapter = AIReliabilityPackageAdapter()
    assert adapter.is_healthy() is True
    status = adapter.health_status()
    assert status["enabled"] is True
    assert status["healthy"] is True
    assert status["version"] == "0.1.0"
    assert status["package_name"] == "aireliability"
    assert status["runtime_status"] == "operational"


def test_aegis_to_aireliability_trace_mapping() -> None:
    """Tests typed conversion between AEGIS ExecutionRecordDTO and aireliability ExecutionTrace."""
    org_id = uuid4()
    record = ExecutionRecordDTO(
        organization_id=org_id,
        service_name="payment-service",
        operation="investigate_redis_timeout",
        provider="ollama-primary",
        model="qwen2.5-coder:7b",
        duration_ms=340.5,
        status=ReliabilityStatus.FAILED,
        input_tokens=150,
        output_tokens=75,
        did_fallback=False,
        estimated_cost=0.0025,
        claims_supported=1,
        claims_total=2,
        prompt_text="Investigate cache pool connection failure",
        output_text="Analysis aborted due to downstream timeout",
        error_message="RedisClusterTimeout: could not acquire slot 1024",
        metadata={"incident_id": "INC-002"},
    )

    adapter = AIReliabilityPackageAdapter()
    trace = adapter._map_to_aireliability_trace(record)

    assert trace is not None
    assert trace.trace_id == record.record_id
    assert trace.status.value == "failed"
    assert trace.latency_ms == 340.5
    assert trace.cost == 0.0025
    assert trace.token_usage["prompt_tokens"] == 150
    assert trace.token_usage["completion_tokens"] == 75
    assert trace.token_usage["total_tokens"] == 225
    assert len(trace.steps) == 1
    assert trace.steps[0].name == "payment-service.investigate_redis_timeout"
    assert trace.steps[0].metadata["error"] == "RedisClusterTimeout: could not acquire slot 1024"
    assert trace.metadata["organization_id"] == str(org_id)


def test_trace_diagnosis_success_execution() -> None:
    """Verifies that a clean/successful trace returns PASS diagnosis."""
    org_id = uuid4()
    record = ExecutionRecordDTO(
        organization_id=org_id,
        service_name="order-service",
        operation="reasoning",
        provider="mock-provider",
        model="mock-v1",
        duration_ms=110.0,
        status=ReliabilityStatus.SUCCESS,
        prompt_text="Healthy reasoning request",
        output_text="Everything is operational",
    )

    adapter = AIReliabilityPackageAdapter()
    diag = adapter.analyze_execution_trace(record)

    assert diag.status == "PASS"
    assert diag.trace_id == record.record_id
    assert diag.metadata["package"] == "aireliability"
    assert diag.metadata["package_version"] == "0.1.0"


def test_trace_diagnosis_failure_execution_root_cause() -> None:
    """Verifies that a failed trace triggers real RootCauseAnalyzer from aireliability."""
    org_id = uuid4()
    record = ExecutionRecordDTO(
        organization_id=org_id,
        service_name="database-service",
        operation="query_latency",
        provider="ollama-primary",
        model="qwen2.5-coder:7b",
        duration_ms=4500.0,
        status=ReliabilityStatus.FAILED,
        prompt_text="Analyze pool exhaustion",
        output_text="",
        error_message="OperationalError: database connection pool exhausted (size=50, max=50)",
    )

    adapter = AIReliabilityPackageAdapter()
    diag = adapter.analyze_execution_trace(record)

    assert diag.status == "FAIL"
    assert diag.primary_category == "execution"
    assert "exhausted" in diag.summary.lower() or "exception" in diag.summary.lower()


def test_evaluate_expectations_with_aireliability() -> None:
    """Tests declarative MaxLatency and OutputContains evaluation executed by aireliability."""
    org_id = uuid4()
    record = ExecutionRecordDTO(
        organization_id=org_id,
        service_name="auth-service",
        operation="verify_token",
        provider="mock-provider",
        model="mock-v1",
        duration_ms=150.0,
        status=ReliabilityStatus.SUCCESS,
        prompt_text="Token verification",
        output_text="Verification completed: user authorized and valid.",
    )

    adapter = AIReliabilityPackageAdapter()

    # Case A: Latency 200ms expectation passes
    res_pass = adapter.evaluate_expectations(record, max_latency_ms=200.0, expected_substring="authorized")
    assert res_pass.passed is True
    assert res_pass.score == 1.0
    assert len(res_pass.failures) == 0

    # Case B: Latency 100ms expectation fails
    res_fail = adapter.evaluate_expectations(record, max_latency_ms=100.0)
    assert res_fail.passed is False
    assert res_fail.score == 0.0
    assert len(res_fail.failures) > 0


def test_fail_safe_behavior_on_unhealthy_state() -> None:
    """When the underlying analyzer is uninitialized, adapter fails safely without crashing."""
    adapter = AIReliabilityPackageAdapter(fail_safe=True)
    adapter._analyzer = None  # simulate failure

    assert adapter.is_healthy() is False

    record = ExecutionRecordDTO(
        organization_id=uuid4(),
        service_name="test-service",
        operation="op",
        provider="prov",
        model="mod",
        duration_ms=50.0,
        status=ReliabilityStatus.FAILED,
        error_message="some error",
    )

    diag = adapter.analyze_execution_trace(record)
    assert diag.status == "FAIL"
    assert "unavailable" in diag.summary.lower()

    eval_res = adapter.evaluate_expectations(record, max_latency_ms=100.0)
    assert eval_res.passed is False
