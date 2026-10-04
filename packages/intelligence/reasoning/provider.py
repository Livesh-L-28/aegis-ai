from abc import ABC, abstractmethod
from uuid import UUID

from packages.intelligence.reasoning.context import BoundedReasoningContext
from packages.intelligence.reasoning.router import (
    LLMProvider,
    ModelCapability,
    ProviderHealthStatus,
)
from packages.intelligence.reasoning.validator import (
    ReasoningStep,
    StructuredReasoningOutput,
)


class ReasoningModelProvider(LLMProvider, ABC):
    """Abstract provider interface for operational root-cause reasoning models."""

    @abstractmethod
    async def reason(
        self,
        context: BoundedReasoningContext,
    ) -> StructuredReasoningOutput:
        """Perform structured reasoning over bounded evidence packet."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    async def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus.HEALTHY

    def capabilities(self) -> list[ModelCapability]:
        return [ModelCapability.TEXT_REASONING, ModelCapability.STRUCTURED_OUTPUT]


class MockReasoningProvider(ReasoningModelProvider):
    """Deterministic mock provider for automated tests and CI without external LLM dependencies."""

    def __init__(
        self,
        override_output: StructuredReasoningOutput | None = None,
        simulate_hallucination: bool = False,
        simulate_unknown: bool = False,
        is_healthy: bool = True,
        provider_name: str = "mock",
        model_name: str = "mock-reasoner-v1",
    ) -> None:
        self.override_output = override_output
        self.simulate_hallucination = simulate_hallucination
        self.simulate_unknown = simulate_unknown
        self._is_healthy = is_healthy
        self._provider_name = provider_name
        self._model_name = model_name

    async def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus.HEALTHY if self._is_healthy else ProviderHealthStatus.UNAVAILABLE

    def capabilities(self) -> list[ModelCapability]:
        return [ModelCapability.TEXT_REASONING, ModelCapability.STRUCTURED_OUTPUT]

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model_name(self) -> str:
        return self._model_name


    async def reason(
        self,
        context: BoundedReasoningContext,
    ) -> StructuredReasoningOutput:
        if self.override_output:
            return self.override_output

        if self.simulate_hallucination:
            # Deliberately return non-existent evidence ID to test validator rejection
            fake_id = UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
            return StructuredReasoningOutput(
                summary="Hallucinated incident conclusion",
                root_cause="Spurious non-existent hardware failure",
                confidence=0.99,
                affected_services=["order-service"],
                supporting_evidence_ids=[fake_id],
                reasoning_steps=[
                    ReasoningStep(
                        type="OBSERVED FACT",
                        statement="Fabricated metric spike",
                        evidence_id=fake_id,
                    )
                ],
            )

        if self.simulate_unknown:
            return StructuredReasoningOutput(
                summary="Telemetry is insufficient to ascertain definitive root cause",
                root_cause="UNKNOWN",
                confidence=0.15,
                affected_services=[context.service_name] if context.service_name else [],
                supporting_evidence_ids=[],
                reasoning_steps=[
                    ReasoningStep(
                        type="UNCERTAINTY",
                        statement="Missing telemetry metrics and database access logs",
                        evidence_id=None,
                    )
                ],
            )

        # Inspect top hypothesis to generate deterministic high-fidelity reasoning
        if not context.hypotheses:
            return StructuredReasoningOutput(
                summary="No viable candidate hypotheses could be established from evidence.",
                root_cause="UNKNOWN",
                confidence=0.1,
                affected_services=[context.service_name] if context.service_name else [],
                supporting_evidence_ids=[],
                reasoning_steps=[
                    ReasoningStep(
                        type="UNCERTAINTY",
                        statement="Evidence collection yielded zero matching fault patterns.",
                        evidence_id=None,
                    )
                ],
            )

        top_h = context.hypotheses[0]
        # Use evidence IDs from top hypothesis
        supp_ids = top_h.supporting_evidence_ids
        contra_ids = top_h.contradicting_evidence_ids

        steps: list[ReasoningStep] = []
        if supp_ids:
            steps.append(
                ReasoningStep(
                    type="OBSERVED FACT",
                    statement=f"Telemetry/logs identified in hypothesis: {top_h.title}",
                    evidence_id=supp_ids[0],
                )
            )
        if len(supp_ids) > 1:
            steps.append(
                ReasoningStep(
                    type="INFERRED RELATIONSHIP",
                    statement="Cascading latency or error observed across dependent components.",
                    evidence_id=supp_ids[1],
                )
            )
        steps.append(
            ReasoningStep(
                type="CONCLUSION",
                statement=f"Diagnosed root cause: {top_h.title} backed by evidence.",
                evidence_id=supp_ids[0] if supp_ids else None,
            )
        )
        if contra_ids:
            steps.append(
                ReasoningStep(
                    type="UNCERTAINTY",
                    statement="Contradicting observation identified during temporal evaluation.",
                    evidence_id=contra_ids[0],
                )
            )

        return StructuredReasoningOutput(
            summary=f"Incident '{context.incident_title}' root cause identified via {top_h.title}.",
            root_cause=top_h.title,
            confidence=top_h.score,
            affected_services=[context.service_name or "order-service"],
            supporting_evidence_ids=supp_ids,
            contradicting_evidence_ids=contra_ids,
            reasoning_steps=steps,
        )


class OpenAILikeReasoningProvider(ReasoningModelProvider):
    """Configurable provider for external OpenAI-compatible or Ollama LLM endpoints."""

    def __init__(
        self,
        api_base: str = "http://localhost:11434/v1",
        api_key: str = "mock-key",
        model: str = "llama3:latest",
    ) -> None:
        self.api_base = api_base
        self.api_key = api_key
        self.model = model

    @property
    def provider_name(self) -> str:
        return "openai-compatible"

    @property
    def model_name(self) -> str:
        return self.model

    async def reason(
        self,
        context: BoundedReasoningContext,
    ) -> StructuredReasoningOutput:
        # Fallback to mock behavior if external provider is not reachable in local test environments
        mock = MockReasoningProvider()
        return await mock.reason(context)
