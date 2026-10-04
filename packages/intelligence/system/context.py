from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from packages.intelligence.code.indexer import CodeSymbol, RepositoryIndexer
from packages.intelligence.knowledge.store import knowledge_store
from packages.intelligence.system.registry import ServiceDependency, system_registry


class UnifiedSystemContext(BaseModel):
    service_name: str
    environment: str = "production-sim"
    version: str = "1.0.0"
    runtime_dependencies: list[ServiceDependency] = Field(default_factory=list)
    repository_path: str = ""
    code_symbols: list[CodeSymbol] = Field(default_factory=list)
    relevant_knowledge: list[dict[str, Any]] = Field(default_factory=list)


class UnifiedContextService:
    """Assembles unified machine-readable context across System, Code, and Knowledge layers."""

    @staticmethod
    def build_context(
        organization_id: UUID,
        service_name: str,
        indexer: RepositoryIndexer | None = None,
    ) -> UnifiedSystemContext:
        # 1. System Intelligence: Runtime dependencies
        all_deps = system_registry.list_dependencies(organization_id)
        service_deps = [
            d for d in all_deps
            if d.source_service_name == service_name or d.target_service_name == service_name
        ]

        # 2. Code Intelligence: Symbols extracted from repository
        symbols: list[CodeSymbol] = []
        if indexer:
            symbols = indexer.search_symbols(service_name.replace("-", "_"))

        # 3. Knowledge Intelligence: Runbooks, incidents, docs relevant to service
        knowledge_matches = knowledge_store.hybrid_search(
            organization_id=organization_id,
            query=f"{service_name} troubleshooting runbook guide",
            limit=5,
        )

        formatted_knowledge = [
            {
                "title": m["chunk"].title,
                "section": m["chunk"].section,
                "score": round(m["score"], 4),
                "content": m["chunk"].content[:200] + "..." if len(m["chunk"].content) > 200 else m["chunk"].content,
            }
            for m in knowledge_matches
        ]

        return UnifiedSystemContext(
            service_name=service_name,
            runtime_dependencies=service_deps,
            repository_path=str(indexer.root_dir) if indexer else "",
            code_symbols=symbols[:10],
            relevant_knowledge=formatted_knowledge,
        )
