from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_audit_service,
    get_request_id,
    require_tenant_context,
)
from apps.api.app.services.tenant import AuditService
from packages.intelligence.code.indexer import CodeSymbol, RepositoryIndexer
from packages.intelligence.knowledge.store import (
    DocumentSourceType,
    knowledge_store,
)
from packages.intelligence.system.context import UnifiedContextService, UnifiedSystemContext
from packages.intelligence.system.registry import (
    SystemDependencyGraph,
    system_registry,
)
from packages.security.rbac import AuthenticatedPrincipal, Permission

router = APIRouter(prefix="/intelligence", tags=["Intelligence (System, Code, Knowledge)"])

# Local workspace repository indexer singleton
WORKSPACE_ROOT = Path(__file__).resolve().parents[5]
workspace_indexer = RepositoryIndexer(WORKSPACE_ROOT)


class IngestDocumentRequest(BaseModel):
    title: str
    source_type: DocumentSourceType = DocumentSourceType.RUNBOOK
    source_uri: str = "docs/runbooks"
    content: str


class SearchQueryRequest(BaseModel):
    query: str
    limit: int = Field(default=5, ge=1, le=20)


class SearchResultsResponse(BaseModel):
    query: str
    system_matches: list[str] = Field(default_factory=list)
    code_matches: list[CodeSymbol] = Field(default_factory=list)
    knowledge_matches: list[dict[str, Any]] = Field(default_factory=list)


# --- System Intelligence Endpoints ---
@router.get("/dependency-graph", response_model=SystemDependencyGraph)
async def get_system_dependency_graph(
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> SystemDependencyGraph:
    """Retrieve runtime dependency graph (Nodes & Edges) for current organization."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    return system_registry.get_dependency_graph(org_id)


@router.get("/services/{service_name}/context", response_model=UnifiedSystemContext)
async def get_service_unified_context(
    service_name: str,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> UnifiedSystemContext:
    """Assemble unified machine-readable context (Dependencies, Code symbols, Runbooks) for service."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    return UnifiedContextService.build_context(
        organization_id=org_id,
        service_name=service_name,
        indexer=workspace_indexer,
    )


# --- Code Intelligence Endpoints ---
@router.post("/code/index", status_code=status.HTTP_200_OK)
async def trigger_code_indexing(
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    request_id: str = Depends(get_request_id),
) -> dict[str, Any]:
    """Trigger incremental repository code indexing."""
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Insufficient permissions to index code")

    indexed = workspace_indexer.index_repository()

    await audit_service.log_event(
        organization_id=org_id,
        actor_user_id=principal.user_id,
        action="repository.index.completed",
        resource_type="repository",
        resource_id=str(WORKSPACE_ROOT),
        request_id=request_id,
        metadata={"files_indexed": len(indexed)},
    )
    return {"status": "success", "indexed_files_count": len(indexed)}


@router.post("/code/search", response_model=list[CodeSymbol])
async def search_code_symbols(
    payload: SearchQueryRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[CodeSymbol]:
    """Search code symbols (classes, functions, methods) by name or signature."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    return workspace_indexer.search_symbols(payload.query)[: payload.limit]


# --- Knowledge Intelligence Endpoints ---
@router.post("/knowledge/documents", status_code=status.HTTP_201_CREATED)
async def ingest_knowledge_document(
    payload: IngestDocumentRequest,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    request_id: str = Depends(get_request_id),
) -> dict[str, Any]:
    """Ingest, chunk, embed, and index an operational knowledge document."""
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Insufficient permissions to ingest knowledge")

    doc = knowledge_store.ingest_document(
        organization_id=org_id,
        title=payload.title,
        source_type=payload.source_type,
        source_uri=payload.source_uri,
        content=payload.content,
    )

    await audit_service.log_event(
        organization_id=org_id,
        actor_user_id=principal.user_id,
        action="knowledge.document.created",
        resource_type="document",
        resource_id=str(doc.id),
        request_id=request_id,
        metadata={"title": doc.title, "chunks_count": len(doc.chunks)},
    )
    return {"status": "created", "document_id": str(doc.id), "chunks_count": len(doc.chunks)}


@router.post("/knowledge/search", response_model=list[dict[str, Any]])
async def search_knowledge(
    payload: SearchQueryRequest,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[dict[str, Any]]:
    """Execute hybrid (Vector + Keyword) search across tenant runbooks and documentation."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    raw_results = knowledge_store.hybrid_search(
        organization_id=org_id,
        query=payload.query,
        limit=payload.limit,
    )

    return [
        {
            "id": str(r["chunk"].id),
            "document_id": str(r["chunk"].document_id),
            "title": r["chunk"].title,
            "section": r["chunk"].section,
            "content": r["chunk"].content,
            "score": round(r["score"], 4),
            "provenance": r["provenance"],
        }
        for r in raw_results
    ]


# --- Unified Search Endpoint ---
@router.post("/search", response_model=SearchResultsResponse)
async def unified_search(
    payload: SearchQueryRequest,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> SearchResultsResponse:
    """Unified cross-domain search across System, Code, and Knowledge layers."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    # 1. System search
    q_lower = payload.query.lower()
    system_matches = [
        d.source_service_name
        for d in system_registry.list_dependencies(org_id)
        if q_lower in d.source_service_name or q_lower in d.target_service_name
    ]

    # 2. Code search
    code_matches = workspace_indexer.search_symbols(payload.query)[: payload.limit]

    # 3. Knowledge search
    raw_kw = knowledge_store.hybrid_search(
        organization_id=org_id, query=payload.query, limit=payload.limit
    )
    formatted_kw = [
        {
            "title": r["chunk"].title,
            "section": r["chunk"].section,
            "content": r["chunk"].content[:150],
            "score": round(r["score"], 4),
        }
        for r in raw_kw
    ]

    return SearchResultsResponse(
        query=payload.query,
        system_matches=list(set(system_matches)),
        code_matches=code_matches,
        knowledge_matches=formatted_kw,
    )
