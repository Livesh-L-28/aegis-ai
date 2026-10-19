"""Engineering evidence collector: gathers revision-consistent code symbols, tests, APIs, and models."""

from uuid import UUID

from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.debugging.models import (
    DebuggingEvidenceItem,
    EvidenceRelevanceLevel,
    NormalizedDebuggingIncident,
    StackTraceFrame,
)


class DebuggingEvidenceCollector:
    """Correlates failure incident context with revision Evidence Graph data."""

    def __init__(self, service: EvidenceGraphService) -> None:
        self.service = service

    async def collect_evidence(
        self,
        organization_id: UUID,
        incident: NormalizedDebuggingIncident,
        localized_frames: list[StackTraceFrame],
        max_evidence_items: int = 50,
    ) -> list[DebuggingEvidenceItem]:
        evidence_items: list[DebuggingEvidenceItem] = []
        seen_keys: set[str] = set()

        repo_id = incident.repository_id
        sha = incident.commit_sha

        # 1. Evidence from failure symptom
        symptom_key = f"SYMPTOM:{incident.exception_type}:{incident.title}"
        if symptom_key not in seen_keys:
            seen_keys.add(symptom_key)
            evidence_items.append(
                DebuggingEvidenceItem(
                    evidence_type="FAILURE_SYMPTOM",
                    content=f"Exception: {incident.exception_type}: {incident.exception_message}",
                    confidence=1.0,
                    relevance_level=EvidenceRelevanceLevel.DIRECT_EVIDENCE,
                    provenance="INCIDENT_INGESTION",
                    explanation=f"Reported failure symptom in {incident.environment} environment.",
                    metadata={"service_name": incident.service_name, "route": incident.route},
                )
            )

        # 2. Evidence from localized stack frames and symbols
        internal_files: set[str] = set()
        for frame in localized_frames:
            if not frame.is_resolved:
                continue

            frame_key = f"FRAME:{frame.file_path}:{frame.line_number}:{frame.matched_symbol}"
            if frame_key in seen_keys:
                continue
            seen_keys.add(frame_key)

            internal_files.add(frame.file_path)
            sym_desc = f" in symbol '{frame.matched_symbol}'" if frame.matched_symbol else ""
            evidence_items.append(
                DebuggingEvidenceItem(
                    evidence_type="AST_SYMBOL" if frame.matched_symbol else "SOURCE_FILE",
                    file_path=frame.file_path,
                    symbol_name=frame.matched_symbol,
                    line_range=(frame.line_number, frame.line_number),
                    content=f"Stack frame execution at {frame.file_path}:{frame.line_number}{sym_desc} ({frame.function_name})",
                    confidence=1.0,
                    relevance_level=EvidenceRelevanceLevel.DIRECT_EVIDENCE,
                    provenance="STACK_TRACE_LOCALIZER",
                    explanation=f"Active execution frame during failure: {frame.resolution_note}",
                )
            )

        # 3. Evidence from reverse-dependency affected tests and callers
        if repo_id and sha and internal_files:
            try:
                affected_tests = await self.service.get_affected_tests(
                    organization_id=organization_id,
                    repository_id=repo_id,
                    commit_sha=sha,
                    changed_files=list(internal_files),
                    max_depth=3,
                )
                for t in affected_tests:
                    t_key = f"AFFECTED_TEST:{t}"
                    if t_key not in seen_keys:
                        seen_keys.add(t_key)
                        evidence_items.append(
                            DebuggingEvidenceItem(
                                evidence_type="AFFECTED_TEST",
                                file_path=t,
                                content=f"Downstream candidate test suite: {t}",
                                confidence=0.9,
                                relevance_level=EvidenceRelevanceLevel.SUPPORTING_CONTEXT,
                                provenance="REVERSE_DEPENDENCY_GRAPH",
                                explanation=f"Test covers or imports components in {list(internal_files)} within 3 dependency hops.",
                            )
                        )
            except Exception:
                pass

        # 4. Evidence from System Contracts (APIs, DB Models, Migrations, Configs)
        if repo_id and sha:
            try:
                contracts = await self.service.get_system_contracts(
                    organization_id=organization_id,
                    repository_id=repo_id,
                    commit_sha=sha,
                )

                # Check API contracts
                for ep in contracts.get("api_endpoints", []):
                    route_path = ep.get("route_path", "")
                    file_path = ep.get("file_path", "")
                    if (
                        (incident.route and incident.route in route_path)
                        or (file_path in internal_files)
                    ):
                        c_key = f"API_CONTRACT:{route_path}"
                        if c_key not in seen_keys:
                            seen_keys.add(c_key)
                            evidence_items.append(
                                DebuggingEvidenceItem(
                                    evidence_type="API_CONTRACT",
                                    file_path=file_path,
                                    symbol_name=f"{ep.get('http_method')} {route_path}",
                                    content=f"FastAPI route {ep.get('http_method')} {route_path} -> {ep.get('handler_name')}",
                                    confidence=1.0,
                                    relevance_level=EvidenceRelevanceLevel.SUPPORTING_CONTEXT,
                                    provenance="SYSTEM_INTELLIGENCE",
                                    explanation=f"Active API contract matching incident route '{incident.route}' or failure file '{file_path}'.",
                                    metadata=ep,
                                )
                            )

                # Check Database Models
                for dm in contracts.get("database_models", []):
                    table_name = dm.get("table_name", "")
                    file_path = dm.get("file_path", "")
                    class_name = dm.get("class_name", "")
                    # Correlate with message or files
                    if (
                        table_name in incident.exception_message.lower()
                        or class_name.lower() in incident.exception_message.lower()
                        or file_path in internal_files
                    ):
                        m_key = f"DB_MODEL:{table_name}"
                        if m_key not in seen_keys:
                            seen_keys.add(m_key)
                            evidence_items.append(
                                DebuggingEvidenceItem(
                                    evidence_type="DATABASE_MODEL",
                                    file_path=file_path,
                                    symbol_name=class_name,
                                    content=f"SQLAlchemy model {class_name} mapped to table '{table_name}'",
                                    confidence=1.0,
                                    relevance_level=EvidenceRelevanceLevel.SUPPORTING_CONTEXT,
                                    provenance="SYSTEM_INTELLIGENCE",
                                    explanation=f"Database model referenced in failure traceback or exception: {table_name}",
                                    metadata=dm,
                                )
                            )

                # Check Configuration references
                for cf in contracts.get("config_references", []):
                    config_key = cf.get("config_key", "")
                    file_path = cf.get("file_path", "")
                    if config_key.lower() in incident.exception_message.lower() or file_path in internal_files:
                        cfg_key = f"CONFIG:{config_key}"
                        if cfg_key not in seen_keys:
                            seen_keys.add(cfg_key)
                            evidence_items.append(
                                DebuggingEvidenceItem(
                                    evidence_type="CONFIGURATION",
                                    file_path=file_path,
                                    symbol_name=config_key,
                                    content=f"Configuration reference to environment key '{config_key}'",
                                    confidence=1.0,
                                    relevance_level=EvidenceRelevanceLevel.SUPPORTING_CONTEXT,
                                    provenance="SYSTEM_INTELLIGENCE",
                                    explanation=f"Configuration key '{config_key}' referenced in failure path.",
                                    metadata={"config_key": config_key},
                                )
                            )
            except Exception:
                pass

        # 5. Evidence from logs or test output
        if incident.test_output:
            ev_test_key = "TEST_OUTPUT"
            if ev_test_key not in seen_keys:
                seen_keys.add(ev_test_key)
                evidence_items.append(
                    DebuggingEvidenceItem(
                        evidence_type="TEST_FAILURE",
                        content=f"Test failure output:\n{incident.test_output[:1000]}",
                        confidence=0.95,
                        relevance_level=EvidenceRelevanceLevel.DIRECT_EVIDENCE,
                        provenance="TEST_RUNNER",
                        explanation="Observed failure output from automated test run.",
                    )
                )

        return evidence_items[:max_evidence_items]
