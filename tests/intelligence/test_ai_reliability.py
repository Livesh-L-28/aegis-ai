"""Phase 5 AI Reliability Engine tests: Metrics, cost calculation, and hallucination indicators."""

from uuid import uuid4

from packages.intelligence.reasoning.reliability import AIReliabilityService


def test_reliability_metrics_aggregation() -> None:
    service = AIReliabilityService()
    org_a = uuid4()
    org_b = uuid4()

    # Org A: 3 successful, 1 timeout, 1 firewall block
    service.record_execution(
        organization_id=org_a,
        operation="reasoning",
        provider="ollama-primary",
        model="qwen2.5-coder:7b",
        duration_ms=120.0,
        status="SUCCESS",
        input_tokens=500,
        output_tokens=250,
        estimated_cost=0.0012,
        claims_supported=3,
        claims_total=3,
    )
    service.record_execution(
        organization_id=org_a,
        operation="reasoning",
        provider="ollama-primary",
        model="qwen2.5-coder:7b",
        duration_ms=150.0,
        status="SUCCESS",
        input_tokens=600,
        output_tokens=300,
        estimated_cost=0.0015,
        claims_supported=2,
        claims_total=2,
    )
    service.record_execution(
        organization_id=org_a,
        operation="reasoning",
        provider="ollama-primary",
        model="qwen2.5-coder:7b",
        duration_ms=100.0,
        status="FIREWALL_BLOCKED",
    )
    service.record_execution(
        organization_id=org_a,
        operation="reasoning",
        provider="ollama-primary",
        model="qwen2.5-coder:7b",
        duration_ms=500.0,
        status="TIMEOUT",
    )

    # Org B: 1 execution
    service.record_execution(
        organization_id=org_b,
        operation="reasoning",
        provider="mock-provider",
        model="mock-v1",
        duration_ms=50.0,
        status="SUCCESS",
    )

    # Verify Org A tenant isolation
    summary_a = service.get_summary(organization_id=org_a)
    assert summary_a.total_requests == 4
    assert summary_a.successful_requests == 2
    assert summary_a.failed_requests == 1
    assert summary_a.total_input_tokens == 1100
    assert summary_a.total_output_tokens == 550
    assert summary_a.total_cost_usd > 0.0
    assert summary_a.reliability_score > 0.0

    # Verify Org B tenant isolation
    summary_b = service.get_summary(organization_id=org_b)
    assert summary_b.total_requests == 1
    assert summary_b.successful_requests == 1
