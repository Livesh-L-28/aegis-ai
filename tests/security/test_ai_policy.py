"""Phase 5 Policy Engine tests: Model whitelisting, data classification, and risk boundary."""

from uuid import uuid4

from packages.security.policy import (
    AIPolicyEngine,
    AIRiskLevel,
    DataClassification,
)


def test_policy_allows_whitelisted_models() -> None:
    policy_engine = AIPolicyEngine()
    org_id = uuid4()

    decision = policy_engine.evaluate_reasoning_request(
        organization_id=org_id,
        model_name="qwen2.5-coder:7b",
        provider_name="ollama-primary",
        prompt="Analyze error trace for service cart-service",
    )
    assert decision.allowed
    assert decision.risk_level == AIRiskLevel.READ_ONLY
    assert decision.data_classification == DataClassification.INTERNAL


def test_policy_denies_disallowed_models() -> None:
    policy_engine = AIPolicyEngine()
    org_id = uuid4()

    decision = policy_engine.evaluate_reasoning_request(
        organization_id=org_id,
        model_name="unauthorized-experimental-model-x",
        provider_name="external-unknown-provider",
        prompt="Analyze error trace",
    )
    assert not decision.allowed
    assert "not permitted" in decision.reason.lower()


def test_policy_blocks_unredacted_secrets() -> None:
    policy_engine = AIPolicyEngine()
    org_id = uuid4()

    decision = policy_engine.evaluate_reasoning_request(
        organization_id=org_id,
        model_name="qwen2.5-coder:7b",
        provider_name="ollama-primary",
        prompt="Authorization: Bearer sk-ant-api03-secret-key-123456789",
    )
    assert not decision.allowed
    assert decision.data_classification == DataClassification.SECRET
    assert "secret" in decision.reason.lower()


def test_policy_blocks_critical_and_high_risk_operations() -> None:
    policy_engine = AIPolicyEngine()

    assert not policy_engine.evaluate_operation(AIRiskLevel.CRITICAL).allowed
    assert not policy_engine.evaluate_operation(AIRiskLevel.HIGH).allowed
    assert policy_engine.evaluate_operation(AIRiskLevel.READ_ONLY).allowed
