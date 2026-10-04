"""Unit tests for Phase 7 Bounded Reliability Agent and Runaway Guardrails."""

from uuid import uuid4

import pytest

from packages.autonomy.domain.enums import AgentExecutionState, AutonomyLevel
from packages.autonomy.domain.models import AgentBudget, AutonomyPolicy
from packages.autonomy.services.agent import ReliabilityAgent
from packages.intelligence.reasoning.validator import StructuredReasoningOutput
from packages.remediation.domain.enums import RemediationActionType
from packages.security.policy import AIRiskLevel


@pytest.mark.asyncio
async def test_bounded_agent_successful_incident_loop() -> None:
    agent = ReliabilityAgent()
    org_id = uuid4()
    inc_id = uuid4()

    policy = AutonomyPolicy(
        organization_id=org_id,
        autonomy_level=AutonomyLevel.LEVEL_2,
        allowed_actions=[RemediationActionType.SERVICE_RESTART],
        maximum_risk=AIRiskLevel.LOW,
    )

    reasoning = StructuredReasoningOutput(
        summary="Transient payment service timeout",
        root_cause="payment-service ephemeral failure",
        confidence=0.95,
        affected_services=["payment-service"],
        supporting_evidence_ids=[],
    )

    run, proposal, learning = await agent.run_incident_loop(
        incident_id=inc_id,
        organization_id=org_id,
        service_name="payment-service",
        reasoning_output=reasoning,
        policy=policy,
        budget=AgentBudget(max_iterations=10, max_tool_calls=10),
    )

    assert run.state == AgentExecutionState.COMPLETED
    assert proposal is not None
    assert run.tool_calls_count > 0
    assert run.total_cost_usd > 0.0
    assert learning is not None
    assert learning.runbook_candidate is True
    assert "payment-service" in learning.proposed_runbook_content


@pytest.mark.asyncio
async def test_runaway_agent_tool_budget_violation() -> None:
    agent = ReliabilityAgent()
    org_id = uuid4()
    inc_id = uuid4()

    policy = AutonomyPolicy(organization_id=org_id)
    reasoning = StructuredReasoningOutput(
        summary="Test runaway",
        root_cause="Generic degradation",
        confidence=0.90,
        affected_services=["order-service"],
        supporting_evidence_ids=[],
    )

    # Restrict budget to only 1 tool call
    budget = AgentBudget(max_tool_calls=1, max_iterations=10)

    run, _proposal, _learning = await agent.run_incident_loop(
        incident_id=inc_id,
        organization_id=org_id,
        service_name="order-service",
        reasoning_output=reasoning,
        policy=policy,
        budget=budget,
    )

    assert run.state == AgentExecutionState.FAILED
    assert "tool call budget" in (run.error_message or "").lower()


@pytest.mark.asyncio
async def test_agent_escalates_to_human_when_policy_requires_approval() -> None:
    agent = ReliabilityAgent()
    org_id = uuid4()
    inc_id = uuid4()

    policy = AutonomyPolicy(
        organization_id=org_id,
        autonomy_level=AutonomyLevel.LEVEL_1,  # Recommend only
    )

    reasoning = StructuredReasoningOutput(
        summary="Database pool issue",
        root_cause="postgres latency",
        confidence=0.90,
        affected_services=["order-service"],
        supporting_evidence_ids=[],
    )

    run, proposal, learning = await agent.run_incident_loop(
        incident_id=inc_id,
        organization_id=org_id,
        service_name="order-service",
        reasoning_output=reasoning,
        policy=policy,
    )

    assert run.state == AgentExecutionState.AWAITING_APPROVAL
    assert proposal is not None
    assert learning is None
