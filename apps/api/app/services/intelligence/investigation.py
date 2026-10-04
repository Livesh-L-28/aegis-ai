"""Investigation orchestration service: manages evidence collection, correlation, hypothesis scoring, and reasoning lifecycle."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.exceptions import (
    ConflictException,
    ResourceNotFoundException,
)
from apps.api.app.models.entities import (
    Evidence,
    Hypothesis,
    Incident,
    Investigation,
    ReasoningResult,
)
from apps.api.app.repositories.investigation import (
    EvidenceRepository,
    HypothesisRepository,
    IncidentRepository,
    InvestigationRepository,
    ReasoningResultRepository,
)
from apps.api.app.services.tenant import AuditService
from packages.intelligence.evidence.engine import EvidenceEngine
from packages.intelligence.evidence.models import EvidenceItem
from packages.intelligence.reasoning.context import ReasoningContextBuilder
from packages.intelligence.reasoning.hypotheses import HypothesisEngine
from packages.intelligence.reasoning.provider import (
    MockReasoningProvider,
    ReasoningModelProvider,
)
from packages.intelligence.reasoning.reliability import (
    AIReliabilityService,
    default_reliability_service,
)
from packages.intelligence.reasoning.router import ModelRouter
from packages.intelligence.reasoning.validator import (
    GroundingValidator,
)
from packages.logging.logger import get_logger
from packages.security.llm_firewall.adapter import (
    FirewallDecisionAction,
    LLMFirewall,
    default_llm_firewall,
)
from packages.security.policy import (
    AIPolicyEngine,
    default_policy_engine,
)

logger = get_logger("aegis.investigation")


class InvestigationService:
    """End-to-end orchestrator for operational incident investigations."""

    def __init__(
        self,
        session: AsyncSession,
        evidence_engine: EvidenceEngine | None = None,
        hypothesis_engine: HypothesisEngine | None = None,
        context_builder: ReasoningContextBuilder | None = None,
        reasoning_provider: ReasoningModelProvider | None = None,
        firewall: LLMFirewall | None = None,
        policy_engine: AIPolicyEngine | None = None,
        reliability_service: AIReliabilityService | None = None,
        fallback_providers: list[ReasoningModelProvider] | None = None,
    ) -> None:
        self.session = session
        self.incident_repo = IncidentRepository(session)
        self.investigation_repo = InvestigationRepository(session)
        self.evidence_repo = EvidenceRepository(session)
        self.hypothesis_repo = HypothesisRepository(session)
        self.reasoning_repo = ReasoningResultRepository(session)
        self.audit_service = AuditService(session)

        self.evidence_engine = evidence_engine or EvidenceEngine()
        self.hypothesis_engine = hypothesis_engine or HypothesisEngine()
        self.context_builder = context_builder or ReasoningContextBuilder()
        self.reasoning_provider = reasoning_provider or MockReasoningProvider()
        self.firewall = firewall or default_llm_firewall
        self.policy_engine = policy_engine or default_policy_engine
        self.reliability_service = reliability_service or default_reliability_service

        # Initialize ModelRouter with primary provider and optional fallbacks
        self.model_router = ModelRouter(
            primary_provider=self.reasoning_provider,
            fallback_providers=fallback_providers or [],
        )

    async def create_incident(
        self,
        organization_id: UUID,
        title: str,
        description: str = "",
        severity: str = "MEDIUM",
        service_name: str | None = None,
        source: str = "MANUAL",
        metadata: dict[str, Any] | None = None,
        actor_id: str = "system",
    ) -> Incident:
        incident = Incident(
            organization_id=organization_id,
            title=title,
            description=description,
            severity=severity,
            status="OPEN",
            source=source,
            service_name=service_name,
            incident_metadata=metadata or {},
        )
        created = await self.incident_repo.create(incident)
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=actor_id,
            action="incident.created",
            resource_type="incident",
            resource_id=str(created.id),
            metadata={"title": title, "severity": severity, "service_name": service_name},
        )
        return created

    async def get_incident(self, incident_id: UUID, organization_id: UUID) -> Incident:
        incident = await self.incident_repo.get_by_id_and_org(incident_id, organization_id)
        if not incident:
            raise ResourceNotFoundException("Incident", incident_id)
        return incident

    async def list_incidents(
        self, organization_id: UUID, limit: int = 50, offset: int = 0
    ) -> Sequence[Incident]:
        return await self.incident_repo.list_by_organization(organization_id, limit, offset)

    async def create_investigation(
        self,
        incident_id: UUID,
        organization_id: UUID,
        created_by: str = "system",
        metadata: dict[str, Any] | None = None,
    ) -> Investigation:
        incident = await self.get_incident(incident_id, organization_id)
        investigation = Investigation(
            organization_id=organization_id,
            incident_id=incident.id,
            status="CREATED",
            created_by=created_by,
            investigation_metadata=metadata or {},
        )
        created = await self.investigation_repo.create(investigation)
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=created_by,
            action="investigation.created",
            resource_type="investigation",
            resource_id=str(created.id),
            metadata={"incident_id": str(incident.id)},
        )
        return created

    async def get_investigation(
        self, investigation_id: UUID, organization_id: UUID
    ) -> Investigation:
        inv = await self.investigation_repo.get_by_id_and_org(investigation_id, organization_id)
        if not inv:
            raise ResourceNotFoundException("Investigation", investigation_id)
        return inv

    async def list_investigations_for_incident(
        self, incident_id: UUID, organization_id: UUID, limit: int = 50, offset: int = 0
    ) -> Sequence[Investigation]:
        await self.get_incident(incident_id, organization_id)
        return await self.investigation_repo.list_by_incident(incident_id, organization_id, limit, offset)

    async def run_investigation(
        self,
        investigation_id: UUID,
        organization_id: UUID,
        actor_id: str = "system",
        override_context: dict[str, Any] | None = None,
    ) -> Investigation:
        """Executes the deterministic evidence collection, correlation, hypothesis scoring, and LLM reasoning pipeline."""
        inv = await self.get_investigation(investigation_id, organization_id)

        # Idempotency check: Reject duplicate runs if already running
        if inv.status in ("COLLECTING_EVIDENCE", "ANALYZING", "REASONING"):
            raise ConflictException(f"Investigation {investigation_id} is already in progress ({inv.status})")

        # Lifecycle: Transition to COLLECTING_EVIDENCE
        inv.status = "COLLECTING_EVIDENCE"
        inv.started_at = datetime.now(UTC)
        await self.investigation_repo.update(inv)
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=actor_id,
            action="investigation.started",
            resource_type="investigation",
            resource_id=str(inv.id),
        )

        try:
            # 1. Evidence Collection
            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=actor_id,
                action="evidence.collection.started",
                resource_type="investigation",
                resource_id=str(inv.id),
            )

            evidence_items: list[EvidenceItem] = await self.evidence_engine.collect_all(
                organization_id=organization_id,
                investigation_id=inv.id,
                service_name=inv.incident.service_name,
                incident_time=inv.incident.detected_at,
                context=override_context,
            )

            # Persist Evidence to DB
            for item in evidence_items:
                ev_entity = Evidence(
                    id=item.id,
                    organization_id=organization_id,
                    investigation_id=inv.id,
                    evidence_type=item.evidence_type.value,
                    source=item.source,
                    service_name=item.service_name,
                    signal=item.signal,
                    observed_at=item.observed_at,
                    content=item.content,
                    structured_data=item.structured_data,
                    confidence=item.confidence,
                    relevance_score=item.relevance_score,
                    provenance=item.provenance,
                )
                await self.evidence_repo.create(ev_entity)

            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=actor_id,
                action="evidence.collection.completed",
                resource_type="investigation",
                resource_id=str(inv.id),
                metadata={"count": len(evidence_items)},
            )

            # Lifecycle: Transition to ANALYZING
            inv.status = "ANALYZING"
            await self.investigation_repo.update(inv)

            # 2. Timeline Construction
            timeline = self.evidence_engine.construct_timeline(evidence_items, inv.incident.title)

            # 3. Hypothesis Generation & Scoring
            hypotheses = self.hypothesis_engine.generate_hypotheses(
                investigation_id=inv.id,
                evidence=evidence_items,
                service_name=inv.incident.service_name,
            )

            # Persist Hypotheses
            for h in hypotheses:
                h_entity = Hypothesis(
                    id=h.id,
                    organization_id=organization_id,
                    investigation_id=inv.id,
                    title=h.title,
                    description=h.description,
                    status=h.status.value,
                    score=h.score,
                    confidence=h.confidence,
                    supporting_evidence_ids=[str(i) for i in h.supporting_evidence_ids],
                    contradicting_evidence_ids=[str(i) for i in h.contradicting_evidence_ids],
                    reasoning=h.reasoning,
                )
                await self.hypothesis_repo.create(h_entity)

            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=actor_id,
                action="hypothesis.generated",
                resource_type="investigation",
                resource_id=str(inv.id),
                metadata={"count": len(hypotheses)},
            )

            # Lifecycle: Transition to REASONING
            inv.status = "REASONING"
            await self.investigation_repo.update(inv)
            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=actor_id,
                action="reasoning.started",
                resource_type="investigation",
                resource_id=str(inv.id),
            )

            # 4. Build Bounded Reasoning Context
            bounded_ctx = self.context_builder.build_context(
                incident_id=inv.incident.id,
                investigation_id=inv.id,
                incident_title=inv.incident.title,
                incident_description=inv.incident.description,
                incident_severity=inv.incident.severity,
                detected_at=inv.incident.detected_at.isoformat(),
                service_name=inv.incident.service_name,
                evidence=evidence_items,
                timeline=timeline,
                hypotheses=hypotheses,
            )

            # --- PHASE 5 TRUST PLANE GATES ---
            t_ai_start = datetime.now(UTC)

            # Gate A: Input Firewall Inspection (llmfirewall-core)
            fw_prompt_scan = self.firewall.inspect_prompt(
                prompt=bounded_ctx.user_prompt,
                user_id=actor_id,
                session_id=str(inv.id),
            )
            if not fw_prompt_scan.allowed or fw_prompt_scan.action == FirewallDecisionAction.BLOCK:
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.firewall.blocked",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={"reason": fw_prompt_scan.reason, "risk_score": fw_prompt_scan.risk_score},
                )
                self.reliability_service.record_execution(
                    organization_id=organization_id,
                    operation="reasoning",
                    provider=self.reasoning_provider.provider_name,
                    model=self.reasoning_provider.model_name,
                    duration_ms=fw_prompt_scan.execution_time_ms,
                    status="FIREWALL_BLOCKED",
                )
                raise ValueError(f"Input blocked by LLM Firewall: {fw_prompt_scan.reason}")

            # Gate B: Policy Engine Evaluation
            policy_decision = self.policy_engine.evaluate_reasoning_request(
                organization_id=organization_id,
                model_name=self.reasoning_provider.model_name,
                provider_name=self.reasoning_provider.provider_name,
                prompt=bounded_ctx.user_prompt,
            )
            if not policy_decision.allowed:
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.policy.denied",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={"reason": policy_decision.reason},
                )
                self.reliability_service.record_execution(
                    organization_id=organization_id,
                    operation="reasoning",
                    provider=self.reasoning_provider.provider_name,
                    model=self.reasoning_provider.model_name,
                    duration_ms=0.0,
                    status="POLICY_DENIED",
                )
                raise PermissionError(f"Request denied by AI Policy: {policy_decision.reason}")

            # 5. Model Router Invocation (Health-aware routing, circuit-breaker, retries, fallback)
            model_out, chosen_provider, chosen_model, did_fallback = await self.model_router.execute_reasoning(
                bounded_ctx
            )
            if did_fallback:
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.model.fallback",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={"fallback_provider": chosen_provider, "fallback_model": chosen_model},
                )

            # Gate C: Output Firewall Inspection
            fw_output_scan = self.firewall.inspect_output(
                generation=model_out.summary + " " + model_out.root_cause,
                user_id=actor_id,
                session_id=str(inv.id),
            )
            if not fw_output_scan.allowed or fw_output_scan.action == FirewallDecisionAction.BLOCK:
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.output.rejected",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={"reason": fw_output_scan.reason},
                )
                raise ValueError(f"Output rejected by LLM Firewall: {fw_output_scan.reason}")

            # 6. Rigorous Groundedness & Hallucination Validation
            try:
                GroundingValidator.validate_groundedness(model_out, evidence_items)
            except Exception as g_exc:
                self.reliability_service.record_execution(
                    organization_id=organization_id,
                    operation="reasoning",
                    provider=chosen_provider,
                    model=chosen_model,
                    duration_ms=(datetime.now(UTC) - t_ai_start).total_seconds() * 1000.0,
                    status="GROUNDING_FAILED",
                    claims_supported=0,
                    claims_total=len(model_out.supporting_evidence_ids) or 1,
                )
                raise g_exc

            # Calculate Final Grounded Confidence
            supp_evidence = [e for e in evidence_items if e.id in model_out.supporting_evidence_ids]
            contra_evidence = [e for e in evidence_items if e.id in model_out.contradicting_evidence_ids]
            is_unk = model_out.root_cause == "UNKNOWN"

            final_confidence = GroundingValidator.calculate_final_confidence(
                model_confidence=model_out.confidence,
                supporting_evidence=supp_evidence,
                contradicting_evidence=contra_evidence,
                is_unknown=is_unk,
            )

            # Record successful execution metrics
            duration_ms = (datetime.now(UTC) - t_ai_start).total_seconds() * 1000.0
            self.reliability_service.record_execution(
                organization_id=organization_id,
                operation="reasoning",
                provider=chosen_provider,
                model=chosen_model,
                duration_ms=duration_ms,
                status="SUCCESS",
                input_tokens=len(bounded_ctx.user_prompt.split()),
                output_tokens=len(model_out.summary.split()),
                did_fallback=did_fallback,
                claims_supported=len(supp_evidence),
                claims_total=len(supp_evidence) + len(contra_evidence) or 1,
            )

            # 7. Persist Structured Reasoning Result
            res_entity = ReasoningResult(
                organization_id=organization_id,
                investigation_id=inv.id,
                summary=model_out.summary,
                root_cause=model_out.root_cause,
                confidence=final_confidence,
                affected_services=model_out.affected_services,
                supporting_evidence_ids=[str(i) for i in model_out.supporting_evidence_ids],
                contradicting_evidence_ids=[str(i) for i in model_out.contradicting_evidence_ids],
                reasoning_steps=[s.model_dump(mode="json") for s in model_out.reasoning_steps],
                model_provider=chosen_provider,
                model_name=chosen_model,
                prompt_version=bounded_ctx.prompt_version,
                context_hash=bounded_ctx.context_hash,
            )
            await self.reasoning_repo.create(res_entity)

            # Optional deep causal trace analysis via aireliability
            try:
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.reliability.analysis.started",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={"provider": chosen_provider, "model": chosen_model},
                )
                diag_result = self.reliability_service.analyze_execution({
                    "organization_id": organization_id,
                    "service_name": inv.incident.service_name or "unknown",
                    "operation": "investigation_reasoning",
                    "provider": chosen_provider,
                    "model": chosen_model,
                    "duration_ms": duration_ms,
                    "status": "SUCCESS",
                    "input_tokens": len(bounded_ctx.user_prompt.split()),
                    "output_tokens": len(model_out.summary.split()),
                    "metadata": {
                        "prompt": bounded_ctx.user_prompt[:500],
                        "output": model_out.summary[:500],
                    },
                })
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.reliability.analysis.completed",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={
                        "report_id": diag_result.report_id,
                        "status": diag_result.status,
                        "primary_category": diag_result.primary_category,
                    },
                )
            except Exception as r_exc:
                logger.warning("aireliability trace analysis skipped or failed: %s", r_exc)
                await self.audit_service.log_event(
                    organization_id=organization_id,
                    actor_user_id=actor_id,
                    action="ai.reliability.analysis.failed",
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    metadata={"error": str(r_exc)},
                )

            # Update Investigation Completion State
            inv.status = "COMPLETED"
            inv.summary = model_out.summary
            inv.confidence = final_confidence
            inv.completed_at = datetime.now(UTC)
            updated = await self.investigation_repo.update(inv)

            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=actor_id,
                action="reasoning.completed",
                resource_type="investigation",
                resource_id=str(inv.id),
                metadata={"root_cause": model_out.root_cause, "confidence": final_confidence},
            )
            return updated

        except Exception as exc:
            logger.error("Investigation %s failed: %s", inv.id, exc, exc_info=True)
            inv.status = "FAILED"
            inv.completed_at = datetime.now(UTC)
            await self.investigation_repo.update(inv)
            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=actor_id,
                action="reasoning.failed",
                resource_type="investigation",
                resource_id=str(inv.id),
                metadata={"error": str(exc)},
            )
            raise
