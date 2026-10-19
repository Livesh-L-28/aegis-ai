"""FastAPI router for Engineering Evidence Graph endpoints with strict tenant isolation."""

import re
import time
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import get_db_session, require_tenant_context
from apps.api.app.repositories.evidence_graph import EvidenceGraphRepository
from apps.api.app.schemas.domain import (
    AffectedTestsResponse,
    ChangeImpactRequest,
    ChangeImpactResponse,
    CodeSymbolResponse,
    EngineeringEvidenceResponse,
    PaginatedEvidenceResponse,
    PaginatedSymbolsResponse,
    ParserCapabilitiesResponse,
    ParserCapabilityItem,
    SystemContractsResponse,
)
from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.code.impact_analysis import ChangeImpactAnalyzer
from packages.intelligence.code.parser_base import default_parser_registry
from packages.security.rbac import AuthenticatedPrincipal, Permission
from packages.service_runtime.metrics import AEGIS_EVIDENCE_IMPACT_QUERY_DURATION_SECONDS

router = APIRouter(prefix="/evidence-graph", tags=["Engineering Evidence Graph"])

SHA_REGEX = re.compile(r"^[0-9a-fA-F]{7,64}$")
PROTECTED_FILES = {"render_schema.json"}


def validate_commit_sha(sha: str) -> str:
    cleaned = sha.strip()
    if not SHA_REGEX.match(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid commit SHA format. Must be a 7-64 hexadecimal string.",
        )
    return cleaned.lower()


def validate_safe_file_path(path: str) -> str:
    norm = path.replace("\\", "/").strip().lstrip("/")
    if not norm or ".." in norm.split("/") or norm.startswith("/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file path: {path}",
        )
    if any(part in PROTECTED_FILES for part in norm.split("/")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access to protected file is denied",
        )
    return norm


@router.get(
    "/repositories/{repo_id}/revisions/{sha}/symbols",
    response_model=PaginatedSymbolsResponse,
    summary="List AST symbols for a repository revision",
)
async def get_revision_symbols(
    repo_id: UUID,
    sha: str,
    file_path: str | None = Query(None, description="Filter by relative file path"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> PaginatedSymbolsResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    clean_sha = validate_commit_sha(sha)
    clean_path = validate_safe_file_path(file_path) if file_path else None

    repo_layer = EvidenceGraphRepository(session)
    repository = await repo_layer.get_repository_by_id(organization_id=org_id, repository_id=repo_id)
    if not repository:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    revision = await repo_layer.get_revision_by_sha(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
    )
    if not revision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Revision not found")

    service = EvidenceGraphService(session)
    symbols, total = await service.get_symbols_for_revision(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
        file_path=clean_path,
        limit=limit,
        offset=offset,
    )

    items = [
        CodeSymbolResponse(
            id=s.id,
            organization_id=s.organization_id,
            file_node_id=s.file_node_id,
            name=s.name,
            qualified_name=s.qualified_name,
            symbol_type=s.symbol_type,
            start_line=s.start_line,
            end_line=s.end_line,
            signature=s.signature,
            docstring_summary=s.docstring_summary,
            created_at=s.created_at,
        )
        for s in symbols
    ]
    return PaginatedSymbolsResponse(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/repositories/{repo_id}/revisions/{sha}/affected-tests",
    response_model=AffectedTestsResponse,
    summary="Resolve affected tests for changed files via reverse dependency graph",
)
async def get_affected_tests_for_revision(
    repo_id: UUID,
    sha: str,
    files: list[str] = Query(..., description="Changed file paths"),
    max_depth: int = Query(3, ge=1, le=10),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AffectedTestsResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    clean_sha = validate_commit_sha(sha)

    # Flatten comma-separated values if query string passed multiple items in one param
    cleaned_files: list[str] = []
    for item in files:
        for single in item.split(","):
            s = single.strip()
            if s:
                cleaned_files.append(validate_safe_file_path(s))

    if not cleaned_files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one valid file path must be specified.",
        )

    repo_layer = EvidenceGraphRepository(session)
    repository = await repo_layer.get_repository_by_id(organization_id=org_id, repository_id=repo_id)
    if not repository:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    revision = await repo_layer.get_revision_by_sha(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
    )
    if not revision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Revision not found")

    service = EvidenceGraphService(session)
    affected = await service.get_affected_tests(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
        changed_files=cleaned_files,
        max_depth=max_depth,
    )

    return AffectedTestsResponse(
        repository_id=repo_id,
        commit_sha=clean_sha,
        changed_files=cleaned_files,
        affected_tests=affected,
    )


@router.get(
    "/repositories/{repo_id}/evidence",
    response_model=PaginatedEvidenceResponse,
    summary="List engineering evidence records for a repository",
)
async def get_repository_evidence(
    repo_id: UUID,
    commit_sha: str | None = Query(None, description="Optional revision filter"),
    evidence_type: str | None = Query(None, description="Filter by evidence type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> PaginatedEvidenceResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    clean_sha = validate_commit_sha(commit_sha) if commit_sha else None

    repo_layer = EvidenceGraphRepository(session)
    repository = await repo_layer.get_repository_by_id(organization_id=org_id, repository_id=repo_id)
    if not repository:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    service = EvidenceGraphService(session)
    records, total = await service.list_evidence(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
        evidence_type=evidence_type,
        limit=limit,
        offset=offset,
    )

    items = [
        EngineeringEvidenceResponse(
            id=r.id,
            organization_id=r.organization_id,
            repository_id=r.repository_id,
            revision_id=r.revision_id,
            evidence_type=r.evidence_type,
            provenance_source=r.provenance_source,
            file_path=r.file_path,
            start_line=r.start_line,
            end_line=r.end_line,
            symbol_name=r.symbol_name,
            content=r.content,
            structured_payload=r.structured_payload,
            confidence=r.confidence,
            content_hash=r.content_hash,
            validation_status=r.validation_status,
            created_at=r.created_at,
        )
        for r in records
    ]
    return PaginatedEvidenceResponse(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/capabilities",
    response_model=ParserCapabilitiesResponse,
    summary="List supported multi-language parser capabilities",
)
async def get_parser_capabilities(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ParserCapabilitiesResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    caps = default_parser_registry.get_capabilities()
    items = [
        ParserCapabilityItem(
            language=c["language"],
            support_status=c["status"],
            file_extensions=c["extensions"],
            parser_version=c["version"],
            features=["symbols", "dependencies", "signatures"],
        )
        for c in caps.get("supported_languages", [])
    ]
    return ParserCapabilitiesResponse(supported_languages=items, total_parsers=len(items))


@router.post(
    "/repositories/{repo_id}/revisions/{sha}/impact",
    response_model=ChangeImpactResponse,
    summary="Calculate change impact and candidate test selection",
)
async def analyze_change_impact(
    repo_id: UUID,
    sha: str,
    payload: ChangeImpactRequest = Body(...),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ChangeImpactResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    clean_sha = validate_commit_sha(sha)
    validated_files = [validate_safe_file_path(p) for p in payload.changed_files]

    repo_layer = EvidenceGraphRepository(session)
    repository = await repo_layer.get_repository_by_id(organization_id=org_id, repository_id=repo_id)
    if not repository:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    revision = await repo_layer.get_revision_by_sha(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
    )
    if not revision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Revision not found")

    service = EvidenceGraphService(session)
    analyzer = ChangeImpactAnalyzer(service)

    t0 = time.perf_counter()
    report = await analyzer.analyze_impact(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
        changed_files=validated_files,
        max_depth=payload.max_depth,
    )
    AEGIS_EVIDENCE_IMPACT_QUERY_DURATION_SECONDS.observe(time.perf_counter() - t0)

    return ChangeImpactResponse(
        repository_id=report.repository_id,
        commit_sha=report.commit_sha,
        changed_files=report.changed_files,
        affected_symbols=report.affected_symbols,
        affected_tests=report.affected_tests,
        affected_api_endpoints=report.affected_api_endpoints,
        affected_database_models=report.affected_database_models,
        risk_level=report.risk_level.value,
        risk_reasons=report.risk_reasons,
        selection_explanations=report.selection_explanations,
        unresolved_dependencies=report.unresolved_dependencies,
        confidence=report.confidence,
    )


@router.get(
    "/repositories/{repo_id}/revisions/{sha}/api-contracts",
    response_model=SystemContractsResponse,
    summary="Get API, database, migration, and config contracts for a revision",
)
async def get_revision_system_contracts(
    repo_id: UUID,
    sha: str,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> SystemContractsResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    clean_sha = validate_commit_sha(sha)

    repo_layer = EvidenceGraphRepository(session)
    repository = await repo_layer.get_repository_by_id(organization_id=org_id, repository_id=repo_id)
    if not repository:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    revision = await repo_layer.get_revision_by_sha(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
    )
    if not revision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Revision not found")

    service = EvidenceGraphService(session)
    contracts = await service.get_system_contracts(
        organization_id=org_id,
        repository_id=repo_id,
        commit_sha=clean_sha,
    )

    return SystemContractsResponse(
        repository_id=repo_id,
        commit_sha=clean_sha,
        api_endpoints=contracts["api_endpoints"],
        client_api_calls=contracts["client_api_calls"],
        database_models=contracts["database_models"],
        migrations=contracts["migrations"],
        config_references=contracts["config_references"],
    )

