"""Deterministic Evidence Engine: Orchestration, Correlation, Deduplication, and Ranking."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from packages.intelligence.evidence.models import (
    EvidenceItem,
    EvidenceSeverity,
    EvidenceType,
    TimelineEntry,
)
from packages.intelligence.evidence.providers import (
    CodeEvidenceProvider,
    DeploymentEvidenceProvider,
    EvidenceProvider,
    KnowledgeEvidenceProvider,
    SystemEvidenceProvider,
    TelemetryEvidenceProvider,
)
from packages.intelligence.knowledge.store import KnowledgeStore
from packages.intelligence.system.registry import (
    SystemIntelligenceRegistry,
    system_registry,
)


class EvidenceEngine:
    """Orchestrates deterministic multi-source evidence collection, correlation, deduplication, and timeline construction."""

    def __init__(
        self,
        telemetry_provider: EvidenceProvider | None = None,
        deployment_provider: EvidenceProvider | None = None,
        system_provider: EvidenceProvider | None = None,
        code_provider: EvidenceProvider | None = None,
        knowledge_provider: EvidenceProvider | None = None,
        system_reg: SystemIntelligenceRegistry = system_registry,
        knowledge_store: KnowledgeStore | None = None,
    ) -> None:
        self.telemetry_provider = telemetry_provider or TelemetryEvidenceProvider()
        self.deployment_provider = deployment_provider or DeploymentEvidenceProvider()
        self.system_provider = system_provider or SystemEvidenceProvider(registry=system_reg)
        self.code_provider = code_provider or CodeEvidenceProvider()
        self.knowledge_provider = knowledge_provider or KnowledgeEvidenceProvider(store=knowledge_store)
        self.system_reg = system_reg

    async def collect_all(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        incident_time: datetime | None = None,
        window_before_minutes: int = 15,
        window_after_minutes: int = 10,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        """Collects evidence across all providers within the bounded investigation window."""
        t_ref = incident_time or datetime.now(UTC)
        start_time = t_ref - timedelta(minutes=window_before_minutes)
        end_time = t_ref + timedelta(minutes=window_after_minutes)

        collected: list[EvidenceItem] = []

        # 1. Telemetry
        telemetry_items = await self.telemetry_provider.collect(
            organization_id, investigation_id, service_name, start_time, end_time, context
        )
        collected.extend(telemetry_items)

        # 2. Deployments
        deployment_items = await self.deployment_provider.collect(
            organization_id, investigation_id, service_name, start_time, end_time, context
        )
        collected.extend(deployment_items)

        # 3. System topology & dependencies
        system_items = await self.system_provider.collect(
            organization_id, investigation_id, service_name, start_time, end_time, context
        )
        collected.extend(system_items)

        # 4. Code & Commits
        code_items = await self.code_provider.collect(
            organization_id, investigation_id, service_name, start_time, end_time, context
        )
        collected.extend(code_items)

        # 5. Knowledge & Runbooks
        knowledge_items = await self.knowledge_provider.collect(
            organization_id, investigation_id, service_name, start_time, end_time, context
        )
        collected.extend(knowledge_items)

        # Deduplicate, rank, and verify
        deduped = self.deduplicate_evidence(collected)
        ranked = self.rank_evidence(deduped, primary_service=service_name)
        return ranked

    def deduplicate_evidence(self, items: list[EvidenceItem]) -> list[EvidenceItem]:
        """Deterministic deduplication and grouping based on service, type, signal, and provenance."""
        seen: dict[str, EvidenceItem] = {}
        for item in items:
            key = f"{item.evidence_type.value}:{item.service_name or 'any'}:{item.signal}:{item.provenance}"
            if key not in seen:
                seen[key] = item
            else:
                # Merge or keep highest confidence
                if item.confidence > seen[key].confidence:
                    seen[key] = item
        return list(seen.values())

    def rank_evidence(
        self,
        items: list[EvidenceItem],
        primary_service: str | None = None,
    ) -> list[EvidenceItem]:
        """Deterministic scoring and ranking of evidence items.

        Factors:
        - Severity level (CRITICAL=1.0, HIGH=0.85, MEDIUM=0.6, LOW=0.4, INFO=0.3)
        - Service relevance (primary target service gets boost)
        - Evidence type importance (METRIC / LOG / TRACE / DEPLOYMENT vs generic)
        - Provider confidence score
        """
        severity_weights = {
            EvidenceSeverity.CRITICAL: 1.0,
            EvidenceSeverity.HIGH: 0.85,
            EvidenceSeverity.MEDIUM: 0.65,
            EvidenceSeverity.LOW: 0.45,
            EvidenceSeverity.INFO: 0.35,
        }

        type_weights = {
            EvidenceType.METRIC: 1.0,
            EvidenceType.TRACE: 0.95,
            EvidenceType.LOG: 0.90,
            EvidenceType.DEPLOYMENT: 0.85,
            EvidenceType.DEPENDENCY: 0.80,
            EvidenceType.CODE: 0.75,
            EvidenceType.KNOWLEDGE: 0.60,
            EvidenceType.SERVICE: 0.70,
            EvidenceType.COMMIT: 0.70,
            EvidenceType.CONFIGURATION: 0.65,
        }

        for item in items:
            sev_w = severity_weights.get(item.severity, 0.5)
            type_w = type_weights.get(item.evidence_type, 0.5)
            svc_w = 1.0 if (primary_service and item.service_name == primary_service) else 0.8

            # Formula: deterministic composition normalized to 0.0 - 1.0
            score = (sev_w * 0.45) + (type_w * 0.25) + (svc_w * 0.15) + (item.confidence * 0.15)
            item.relevance_score = round(min(1.0, max(0.0, score)), 4)

        # Sort descending by relevance score, then chronologically
        items.sort(key=lambda x: (x.relevance_score, x.observed_at), reverse=True)
        return items

    def construct_timeline(
        self,
        evidence: list[EvidenceItem],
        incident_title: str = "Incident Trigger",
    ) -> list[TimelineEntry]:
        """Builds a structured chronological timeline linking each entry to relevant evidence IDs."""
        # Chronological sort
        sorted_evidence = sorted(evidence, key=lambda x: x.observed_at)
        timeline: list[TimelineEntry] = []

        for item in sorted_evidence:
            title = f"[{item.evidence_type.value}] {item.service_name or 'System'}: {item.signal}"
            entry = TimelineEntry(
                timestamp=item.observed_at,
                title=title,
                description=item.content,
                service_name=item.service_name,
                event_type=item.evidence_type.value,
                evidence_ids=[item.id],
            )
            timeline.append(entry)

        return timeline

    def correlate_dependencies(
        self,
        evidence: list[EvidenceItem],
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Correlates evidence along known architectural dependency paths.

        Example: API -> Order Service -> PostgreSQL
        """
        deps = self.system_reg.list_dependencies(organization_id)
        affected_services = {e.service_name for e in evidence if e.service_name}

        propagation_paths: list[dict[str, str]] = []
        for d in deps:
            if d.source_service_name in affected_services or d.target_service_name in affected_services:
                propagation_paths.append({
                    "from": d.source_service_name,
                    "to": d.target_service_name,
                    "type": d.dependency_type.value,
                })

        return {
            "affected_services": list(affected_services),
            "propagation_paths": propagation_paths,
        }
