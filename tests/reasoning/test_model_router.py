import asyncio
from uuid import uuid4

import pytest

from packages.intelligence.reasoning.context import BoundedReasoningContext
from packages.intelligence.reasoning.provider import MockReasoningProvider
from packages.intelligence.reasoning.router import (
    CircuitBreaker,
    CircuitBreakerState,
    LLMProvider,
    ModelCapability,
    ModelRouter,
    ProviderHealthStatus,
)
from packages.intelligence.reasoning.validator import StructuredReasoningOutput


class FailingMockProvider(LLMProvider):
    def __init__(self, name: str = "failing-provider", delay: float = 0.0) -> None:
        self.name = name
        self.delay = delay

    @property
    def provider_name(self) -> str:
        return self.name

    @property
    def model_name(self) -> str:
        return f"{self.name}-model"

    async def reason(self, context: BoundedReasoningContext) -> StructuredReasoningOutput:
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        raise RuntimeError("Provider connection error")

    async def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus.UNAVAILABLE

    def capabilities(self) -> list[ModelCapability]:
        return [ModelCapability.TEXT_REASONING]


def _build_test_context() -> BoundedReasoningContext:
    return BoundedReasoningContext(
        incident_id=uuid4(),
        investigation_id=uuid4(),
        service_name="cart-service",
        incident_title="Database timeout",
        incident_severity="HIGH",
        context_hash="hash-1234",
        prompt_version="v1",
        system_prompt="You are an SRE reasoning agent.",
        user_prompt="Explain failure",
        top_evidence=[],
        timeline=[],
        hypotheses=[],
    )



@pytest.mark.asyncio
async def test_router_selects_primary_when_healthy() -> None:
    primary = MockReasoningProvider(provider_name="primary-mock", model_name="mock-v1")
    fallback = MockReasoningProvider(provider_name="fallback-mock", model_name="mock-fb")
    router = ModelRouter(primary_provider=primary, fallback_providers=[fallback])

    ctx = _build_test_context()
    output, provider_name, model_name, did_fallback = await router.execute_reasoning(ctx)
    assert provider_name == "primary-mock"
    assert model_name == "mock-v1"
    assert not did_fallback
    assert output.summary is not None


@pytest.mark.asyncio
async def test_router_fails_over_to_fallback_on_primary_failure() -> None:
    primary = FailingMockProvider(name="broken-primary")
    fallback = MockReasoningProvider(provider_name="healthy-fallback", model_name="fb-model")
    router = ModelRouter(primary_provider=primary, fallback_providers=[fallback], max_retries=1)

    ctx = _build_test_context()
    output, provider_name, _model_name, did_fallback = await router.execute_reasoning(ctx)
    assert provider_name == "healthy-fallback"
    assert did_fallback is True
    assert output.summary is not None


@pytest.mark.asyncio
async def test_router_timeout_triggers_fallback() -> None:
    slow_primary = FailingMockProvider(name="slow-primary", delay=0.5)
    fallback = MockReasoningProvider(provider_name="quick-fallback", model_name="qb-model")
    router = ModelRouter(
        primary_provider=slow_primary,
        fallback_providers=[fallback],
        timeout_seconds=0.05,
        max_retries=0,
    )

    ctx = _build_test_context()
    _output, provider_name, _model_name, did_fallback = await router.execute_reasoning(ctx)
    assert provider_name == "quick-fallback"
    assert did_fallback is True




def test_circuit_breaker_transitions() -> None:
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=0.2)
    assert cb.state == CircuitBreakerState.CLOSED
    assert cb.allow_request()

    cb.record_failure()
    assert cb.state == CircuitBreakerState.CLOSED

    cb.record_failure()
    assert cb.state == CircuitBreakerState.OPEN
    assert not cb.allow_request()
