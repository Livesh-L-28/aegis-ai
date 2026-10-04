"""Evidence provider abstraction and collectors for Phase 4 Evidence Engine."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from packages.intelligence.evidence.models import (
    EvidenceItem,
    EvidenceSeverity,
    EvidenceType,
)
from packages.intelligence.knowledge.store import KnowledgeStore
from packages.intelligence.system.registry import (
    SystemIntelligenceRegistry,
    system_registry,
)
from packages.simulation.deployments import DeploymentEvent, deployment_registry
from packages.simulation.scenarios import simulation_registry


class EvidenceProvider(ABC):
    """Abstract interface for all deterministic evidence collection providers."""

    @abstractmethod
    async def collect(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        start_time: datetime,
        end_time: datetime,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        """Collect and normalize evidence items within the bounded investigation window."""
        pass


class TelemetryEvidenceProvider(EvidenceProvider):
    """Collects normalized metric, log, and trace evidence.

    Vendor-neutral abstraction over Prometheus, Loki, OpenTelemetry, or simulation telemetry.
    """

    async def collect(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        start_time: datetime,
        end_time: datetime,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        ctx = context or {}

        # 1. Inspect active or recent simulation telemetry if present in context or registry
        active_scenarios = simulation_registry.list_all()
        for scenario in active_scenarios:
            if not scenario.enabled and not ctx.get(f"scenario_{scenario.id}_active"):
                # Also allow explicit telemetry signals passed in context
                continue

            target = scenario.target_service
            if service_name and target != service_name and not ctx.get("include_all_services", True):
                continue

            # Derive telemetry evidence based on scenario fault type
            if scenario.fault_type.value == "database_latency":
                latency_ms = scenario.parameters.get("latency_ms", 1500)
                evidence.append(
                    EvidenceItem(
                        organization_id=organization_id,
                        investigation_id=investigation_id,
                        evidence_type=EvidenceType.METRIC,
                        source="prometheus",
                        service_name=target,
                        signal="database_query_duration_seconds",
                        severity=EvidenceSeverity.HIGH,
                        content=f"Database query latency spiked by +{latency_ms}ms on {target} (observed: {latency_ms/1000.0:.2f}s, baseline: 0.04s)",
                        structured_data={
                            "metric": "database_query_duration_seconds",
                            "baseline_seconds": 0.04,
                            "observed_seconds": latency_ms / 1000.0,
                            "deviation_seconds": (latency_ms / 1000.0) - 0.04,
                            "operation": "INSERT",
                        },
                        confidence=0.98,
                        provenance=f"prometheus:query(histogram_quantile(0.99, rate(database_query_duration_seconds_bucket[5m]))){{service='{target}'}}",
                    )
                )
                evidence.append(
                    EvidenceItem(
                        organization_id=organization_id,
                        investigation_id=investigation_id,
                        evidence_type=EvidenceType.LOG,
                        source="loki",
                        service_name=target,
                        signal="SLOW_QUERY_WARNING",
                        severity=EvidenceSeverity.MEDIUM,
                        content=f"Database latency warning logged: query took {latency_ms}ms during order persistence",
                        structured_data={"latency_ms": latency_ms, "operation": "order_insert"},
                        confidence=0.95,
                        provenance=f"loki:query({{service='{target}', level='WARNING'}} |= 'database latency')",
                    )
                )

            elif scenario.fault_type.value == "redis_failure":
                evidence.append(
                    EvidenceItem(
                        organization_id=organization_id,
                        investigation_id=investigation_id,
                        evidence_type=EvidenceType.METRIC,
                        source="prometheus",
                        service_name=target,
                        signal="redis_errors_total",
                        severity=EvidenceSeverity.CRITICAL,
                        content=f"Redis command SETEX failed on {target}; counter increased by 100%",
                        structured_data={"metric": "redis_errors_total", "command": "SETEX", "error_rate": 1.0},
                        confidence=0.99,
                        provenance=f"prometheus:query(rate(redis_errors_total{{service='{target}'}}[1m]))",
                    )
                )
                evidence.append(
                    EvidenceItem(
                        organization_id=organization_id,
                        investigation_id=investigation_id,
                        evidence_type=EvidenceType.LOG,
                        source="loki",
                        service_name=target,
                        signal="CONNECTION_ERROR",
                        severity=EvidenceSeverity.HIGH,
                        content="Redis connection breakdown: payment ledger cache unreachable during idempotency check",
                        structured_data={"error": "RedisConnectionError", "command": "SETEX"},
                        confidence=0.97,
                        provenance=f"loki:query({{service='{target}', level='ERROR'}} |= 'Redis connection failed')",
                    )
                )

            elif scenario.fault_type.value == "deployment_regression":
                evidence.append(
                    EvidenceItem(
                        organization_id=organization_id,
                        investigation_id=investigation_id,
                        evidence_type=EvidenceType.METRIC,
                        source="prometheus",
                        service_name=target,
                        signal="orders_failed_total",
                        severity=EvidenceSeverity.HIGH,
                        content=f"Orders failure surge (reason=deployment_regression) on {target}",
                        structured_data={"metric": "orders_failed_total", "reason": "deployment_regression", "rate": 0.5},
                        confidence=0.96,
                        provenance=f"prometheus:query(rate(orders_failed_total{{service='{target}'}}[2m]))",
                    )
                )

        # 2. Check explicitly provided telemetry observations in context
        custom_metrics = ctx.get("metrics", [])
        for m in custom_metrics:
            evidence.append(
                EvidenceItem(
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    evidence_type=EvidenceType.METRIC,
                    source=m.get("source", "prometheus"),
                    service_name=m.get("service_name", service_name),
                    signal=m.get("signal", "metric_deviation"),
                    severity=EvidenceSeverity(m.get("severity", "MEDIUM")),
                    content=m.get("content", "Metric deviation observed"),
                    structured_data=m.get("structured_data", {}),
                    confidence=m.get("confidence", 0.95),
                    provenance=m.get("provenance", "prometheus:query()"),
                )
            )

        custom_logs = ctx.get("logs", [])
        for log_item in custom_logs:
            evidence.append(
                EvidenceItem(
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    evidence_type=EvidenceType.LOG,
                    source=log_item.get("source", "loki"),
                    service_name=log_item.get("service_name", service_name),
                    signal=log_item.get("signal", "error_log"),
                    severity=EvidenceSeverity(log_item.get("severity", "HIGH")),
                    content=log_item.get("content", "Error log detected"),
                    structured_data=log_item.get("structured_data", {}),
                    confidence=log_item.get("confidence", 0.90),
                    provenance=log_item.get("provenance", "loki:query()"),
                )
            )

        custom_traces = ctx.get("traces", [])
        for t in custom_traces:
            evidence.append(
                EvidenceItem(
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    evidence_type=EvidenceType.TRACE,
                    source=t.get("source", "opentelemetry"),
                    service_name=t.get("service_name", service_name),
                    signal=t.get("signal", "slow_span"),
                    severity=EvidenceSeverity(t.get("severity", "HIGH")),
                    content=t.get("content", f"Span {t.get('span_id', 'unknown')} failed or timed out"),
                    structured_data=t.get("structured_data", {}),
                    confidence=t.get("confidence", 0.95),
                    provenance=f"otlp:trace_id={t.get('trace_id', 'unknown')}:span_id={t.get('span_id', 'unknown')}",
                )
            )

        return evidence


class DeploymentEvidenceProvider(EvidenceProvider):
    """Collects recent deployment events, rollouts, and version shifts."""

    def __init__(self, registry: Any = deployment_registry) -> None:
        self.registry = registry

    async def collect(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        start_time: datetime,
        end_time: datetime,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        events: list[DeploymentEvent] = self.registry.list_all(limit=10)

        # Also support explicit deployment passed in context
        ctx = context or {}
        if "deployment" in ctx:
            d = ctx["deployment"]
            events.append(
                DeploymentEvent(
                    service_name=d.get("service_name", service_name or "order-service"),
                    version=d.get("version", "1.1.0"),
                    previous_version=d.get("previous_version", "1.0.0"),
                    commit_sha=d.get("commit_sha", "c7d8e9f0"),
                    metadata=d.get("metadata", {}),
                )
            )

        for ev in events:
            if service_name and ev.service_name != service_name and not ctx.get("include_all_deployments", True):
                continue

            evidence.append(
                EvidenceItem(
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    evidence_type=EvidenceType.DEPLOYMENT,
                    source="deployment-engine",
                    service_name=ev.service_name,
                    signal=f"version:{ev.version}",
                    severity=EvidenceSeverity.INFO,
                    content=f"Deployment of {ev.service_name} to version {ev.version} (commit {ev.commit_sha}) completed",
                    structured_data={
                        "deployment_id": str(ev.deployment_id),
                        "version": ev.version,
                        "previous_version": ev.previous_version,
                        "commit_sha": ev.commit_sha,
                        "environment": ev.environment,
                    },
                    confidence=1.0,
                    provenance=f"deployments:id={ev.deployment_id}:commit={ev.commit_sha}",
                )
            )

        return evidence


class SystemEvidenceProvider(EvidenceProvider):
    """Collects dependency topology paths, upstream/downstream maps, and architecture links."""

    def __init__(self, registry: SystemIntelligenceRegistry = system_registry) -> None:
        self.registry = registry

    async def collect(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        start_time: datetime,
        end_time: datetime,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        deps = self.registry.list_dependencies(organization_id)

        target_service = service_name or "order-service"
        # Find upstream and downstream
        downstream = [d.target_service_name for d in deps if d.source_service_name == target_service]
        upstream = [d.source_service_name for d in deps if d.target_service_name == target_service]

        for d in deps:
            if d.source_service_name == target_service or d.target_service_name == target_service:
                evidence.append(
                    EvidenceItem(
                        organization_id=organization_id,
                        investigation_id=investigation_id,
                        evidence_type=EvidenceType.DEPENDENCY,
                        source="system-registry",
                        service_name=target_service,
                        signal=f"dependency:{d.source_service_name}->{d.target_service_name}",
                        severity=EvidenceSeverity.INFO,
                        content=f"Service dependency: {d.source_service_name} calls {d.target_service_name} via {d.dependency_type.value} ({d.protocol})",
                        structured_data={
                            "source": d.source_service_name,
                            "target": d.target_service_name,
                            "type": d.dependency_type.value,
                            "protocol": d.protocol,
                            "upstream": upstream,
                            "downstream": downstream,
                        },
                        confidence=1.0,
                        provenance=f"topology:edge:{d.source_service_name}->{d.target_service_name}",
                    )
                )

        return evidence


class CodeEvidenceProvider(EvidenceProvider):
    """Collects recent commit logs, symbol definitions, and changed files."""

    async def collect(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        start_time: datetime,
        end_time: datetime,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        ctx = context or {}

        # Code changes can be retrieved from git history or provided in investigation context
        code_changes = ctx.get("code_changes", [])
        if not code_changes and ctx.get("scenario_INC-005_active"):
            code_changes = [
                {
                    "file_path": "apps/simulated_production/order_service/main.py",
                    "commit_sha": "c7d8e9f0",
                    "author": "engineer@aegis.ai",
                    "message": "feat: order processing engine v1.1 optimizations",
                    "changed_symbols": ["create_order"],
                }
            ]

        for change in code_changes:
            evidence.append(
                EvidenceItem(
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    evidence_type=EvidenceType.CODE,
                    source="git",
                    service_name=service_name or "order-service",
                    signal="code_diff",
                    severity=EvidenceSeverity.MEDIUM,
                    content=f"Recent commit {change.get('commit_sha')} modified {change.get('file_path')} affecting symbols: {', '.join(change.get('changed_symbols', []))}",
                    structured_data=change,
                    confidence=0.95,
                    provenance=f"git:commit={change.get('commit_sha')}:file={change.get('file_path')}",
                )
            )

        return evidence


class KnowledgeEvidenceProvider(EvidenceProvider):
    """Retrieves relevant runbooks, postmortems, and architectural guides via knowledge search."""

    def __init__(self, store: KnowledgeStore | None = None) -> None:
        self.store = store

    async def collect(
        self,
        organization_id: UUID,
        investigation_id: UUID,
        service_name: str | None,
        start_time: datetime,
        end_time: datetime,
        context: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        ctx = context or {}

        # Deterministic operational query based on service and observed signals
        query = ctx.get("knowledge_query") or f"{service_name or 'order-service'} latency database timeout degradation"

        if self.store is not None:
            results = self.store.hybrid_search(organization_id, query=query, limit=3)
            for res in results:
                chunk = res.get("chunk")
                score = float(res.get("score", 0.8))
                if chunk is not None:
                    evidence.append(
                        EvidenceItem(
                            organization_id=organization_id,
                            investigation_id=investigation_id,
                            evidence_type=EvidenceType.KNOWLEDGE,
                            source="knowledge-base",
                            service_name=service_name,
                            signal="runbook_match",
                            severity=EvidenceSeverity.INFO,
                            content=f"Knowledge documentation match: '{chunk.title}' ({chunk.section}): {chunk.content[:200]}...",
                            structured_data={
                                "document_id": str(chunk.document_id),
                                "chunk_id": str(chunk.id),
                                "section": chunk.section,
                                "relevance_score": score,
                            },
                            confidence=min(1.0, max(0.5, score)),
                            provenance=f"knowledge:doc={chunk.document_id}:chunk={chunk.id}",
                        )
                    )

        # Fallback operational knowledge runbook if store has no relevant entry
        if not evidence and service_name:
            evidence.append(
                EvidenceItem(
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    evidence_type=EvidenceType.KNOWLEDGE,
                    source="runbook-catalog",
                    service_name=service_name,
                    signal="runbook_reference",
                    severity=EvidenceSeverity.INFO,
                    content=f"Operational Runbook for {service_name}: Verify downstream database pool contention and Redis latency prior to restarting services.",
                    structured_data={"topic": "troubleshooting", "service": service_name},
                    confidence=0.85,
                    provenance=f"runbooks:{service_name}_troubleshooting.md",
                )
            )

        return evidence
