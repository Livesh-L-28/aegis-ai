"""Model Registry, Capabilities, Health, Circuit Breaker, Retries, and Model Router."""

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, Field

from packages.intelligence.reasoning.context import BoundedReasoningContext
from packages.intelligence.reasoning.validator import StructuredReasoningOutput
from packages.logging.logger import get_logger

logger = get_logger("aegis.intelligence.router")


class ModelCapability(StrEnum):
    TEXT_REASONING = "TEXT_REASONING"
    STRUCTURED_OUTPUT = "STRUCTURED_OUTPUT"
    TOOL_CALLING = "TOOL_CALLING"
    CODE_ANALYSIS = "CODE_ANALYSIS"
    LONG_CONTEXT = "LONG_CONTEXT"


class ProviderHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


class CircuitBreakerState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ModelMetadata(BaseModel):
    provider: str
    model: str
    version: str = "1.0"
    capabilities: list[ModelCapability] = Field(default_factory=list)
    context_limit: int = 8192
    enabled: bool = True
    priority: int = 1
    input_cost_per_1k: float | None = None
    output_cost_per_1k: float | None = None


class CircuitBreaker:
    """Protects against cascade degradation by short-circuiting failing AI providers."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.state: CircuitBreakerState = CircuitBreakerState.CLOSED
        self.failure_count: int = 0
        self.last_failure_time: float = 0.0

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker tripped to OPEN after %d failures", self.failure_count)

    def allow_request(self) -> bool:
        if self.state == CircuitBreakerState.CLOSED:
            return True
        if self.state == CircuitBreakerState.OPEN:
            if (time.time() - self.last_failure_time) > self.recovery_timeout_seconds:
                self.state = CircuitBreakerState.HALF_OPEN
                logger.info("Circuit breaker entered HALF_OPEN probe state")
                return True
            return False
        # HALF_OPEN: allow trial request
        return True


class LLMProvider(ABC):
    """Abstract interface for all Phase 5 AI providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @abstractmethod
    async def reason(self, context: BoundedReasoningContext) -> StructuredReasoningOutput:
        pass

    @abstractmethod
    async def health(self) -> ProviderHealthStatus:
        pass

    @abstractmethod
    def capabilities(self) -> list[ModelCapability]:
        pass


class ModelRouter:
    """Selects, protects, times out, retries, and fails over AI reasoning providers."""

    def __init__(
        self,
        primary_provider: LLMProvider,
        fallback_providers: Sequence[LLMProvider] | None = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 1,
    ) -> None:
        self.primary_provider = primary_provider
        self.fallback_providers = list(fallback_providers) if fallback_providers else []

        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self._init_circuit_breaker(self.primary_provider.provider_name)
        for fb in self.fallback_providers:
            self._init_circuit_breaker(fb.provider_name)

    def _init_circuit_breaker(self, name: str) -> None:
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker()

    async def execute_reasoning(
        self,
        context: BoundedReasoningContext,
    ) -> tuple[StructuredReasoningOutput, str, str, bool]:
        """Executes reasoning through primary provider, with health-aware retry, circuit-breaker, and fallback.

        Returns (result, selected_provider_name, selected_model_name, did_fallback).
        """
        providers_to_try = [self.primary_provider, *self.fallback_providers]
        last_error: Exception | None = None


        for idx, provider in enumerate(providers_to_try):
            cb = self.circuit_breakers.get(provider.provider_name, CircuitBreaker())
            if not cb.allow_request():
                logger.warning(
                    "Skipping provider %s because its circuit breaker is OPEN", provider.provider_name
                )
                continue

            did_fallback = idx > 0

            # Attempt execution with retries
            for attempt in range(self.max_retries + 1):
                try:
                    logger.info(
                        "Routing request to provider '%s' (model: '%s', fallback=%s, attempt=%d)",
                        provider.provider_name,
                        provider.model_name,
                        did_fallback,
                        attempt + 1,
                    )
                    # Enforce timeout
                    result = await asyncio.wait_for(
                        provider.reason(context),
                        timeout=self.timeout_seconds,
                    )
                    cb.record_success()
                    return result, provider.provider_name, provider.model_name, did_fallback

                except TimeoutError as exc:
                    logger.error("Provider '%s' timed out after %0.1fs", provider.provider_name, self.timeout_seconds)
                    cb.record_failure()
                    last_error = exc
                except Exception as exc:
                    logger.error("Provider '%s' failed on attempt %d: %s", provider.provider_name, attempt + 1, exc)
                    cb.record_failure()
                    last_error = exc

        # All providers failed or circuit-broken
        raise RuntimeError(f"All AI providers in model router failed or circuit-broken: {last_error}")

    def list_models(self) -> list[ModelMetadata]:
        """List registered models in this router."""
        models: list[ModelMetadata] = []
        for p in [self.primary_provider, *self.fallback_providers]:
            models.append(
                ModelMetadata(
                    provider=p.provider_name,
                    model=p.model_name,
                    version="1.0",
                    capabilities=p.capabilities(),
                    context_limit=8192,
                    enabled=True,
                    priority=1 if p == self.primary_provider else 2,
                    input_cost_per_1k=0.0015,
                    output_cost_per_1k=0.0020,
                )
            )
        return models

    def list_providers(self) -> list[LLMProvider]:
        """List registered providers."""
        return [self.primary_provider, *self.fallback_providers]


    @classmethod
    def get_default_router(cls) -> "ModelRouter":
        global _default_model_router
        if _default_model_router is None:
            from packages.intelligence.reasoning.provider import MockReasoningProvider
            primary = MockReasoningProvider(provider_name="ollama-primary", model_name="qwen2.5-coder:7b")
            fallback = MockReasoningProvider(provider_name="mock-fallback", model_name="aegis-fallback-mock")
            _default_model_router = cls(primary_provider=primary, fallback_providers=[fallback])
        return _default_model_router


_default_model_router: ModelRouter | None = None

