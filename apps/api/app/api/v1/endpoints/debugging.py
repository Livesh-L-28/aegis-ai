"""FastAPI router for Autonomous Debugging endpoints with strict tenant isolation."""

from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import get_db_session, require_tenant_context
from apps.api.app.schemas.domain import (
    DebuggingAnalysisResponse,
    DebuggingCapabilitiesResponse,
    DebuggingEvidenceResponse,
    FixProposalResponse,
    RankedHypothesisResponse,
    StackTraceFrameResponse,
    VerificationStepResponse,
)
from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.debugging.models import (
    DebuggingAnalysisRun,
    DebuggingIncidentInput,
)
from packages.intelligence.debugging.service import AutonomousDebuggingService
from packages.security.rbac import AuthenticatedPrincipal, Permission

router = APIRouter(prefix="/debugging", tags=["Autonomous Debugging"])


def _map_to_analysis_response(run: DebuggingAnalysisRun) -> DebuggingAnalysisResponse:
    return DebuggingAnalysisResponse(
        id=run.id,
        organization_id=run.organization_id,
        status=run.status.value,
        title=run.incident.title,
        exception_type=run.incident.exception_type,
        summary=run.summary,
        started_at=run.started_at,
        completed_at=run.completed_at,
        error_message=run.error_message,
        localized_frames_count=len(run.localized_frames),
        correlated_evidence_count=len(run.correlated_evidence),
        hypotheses_count=len(run.hypotheses),
        fix_proposals_count=len(run.fix_proposals),
    )


@router.get(
    "/capabilities",
    response_model=DebuggingCapabilitiesResponse,
    summary="List autonomous debugging capabilities",
)
async def get_debugging_capabilities(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> DebuggingCapabilitiesResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    caps = AutonomousDebuggingService.get_capabilities()
    return DebuggingCapabilitiesResponse(**caps)


@router.post(
    "/analyses",
    response_model=DebuggingAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit failure incident for autonomous debugging analysis",
)
async def submit_incident_analysis(
    payload: DebuggingIncidentInput = Body(...),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> DebuggingAnalysisResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.start_analysis(organization_id=org_id, payload=payload)
    return _map_to_analysis_response(run)


@router.get(
    "/analyses/{analysis_id}",
    response_model=DebuggingAnalysisResponse,
    summary="Retrieve debugging analysis run status",
)
async def get_analysis_run(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> DebuggingAnalysisResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.get_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return _map_to_analysis_response(run)


@router.get(
    "/analyses/{analysis_id}/frames",
    response_model=list[StackTraceFrameResponse],
    summary="Retrieve localized stack frames for analysis",
)
async def get_analysis_frames(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[StackTraceFrameResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.get_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return [
        StackTraceFrameResponse(
            file_path=f.file_path,
            line_number=f.line_number,
            function_name=f.function_name,
            code_context=f.code_context,
            origin=f.origin.value,
            is_resolved=f.is_resolved,
            matched_symbol=f.matched_symbol,
            is_protected_file=f.is_protected_file,
            resolution_note=f.resolution_note,
        )
        for f in run.localized_frames
    ]


@router.get(
    "/analyses/{analysis_id}/evidence",
    response_model=list[DebuggingEvidenceResponse],
    summary="Retrieve correlated technical evidence for analysis",
)
async def get_analysis_evidence(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[DebuggingEvidenceResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.get_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return [
        DebuggingEvidenceResponse(
            id=e.id,
            evidence_type=e.evidence_type,
            file_path=e.file_path,
            symbol_name=e.symbol_name,
            line_range=e.line_range,
            content=e.content,
            confidence=e.confidence,
            relevance_level=e.relevance_level.value,
            provenance=e.provenance,
            explanation=e.explanation,
            metadata=e.metadata,
        )
        for e in run.correlated_evidence
    ]


@router.get(
    "/analyses/{analysis_id}/hypotheses",
    response_model=list[RankedHypothesisResponse],
    summary="Retrieve ranked root cause hypotheses for analysis",
)
async def get_analysis_hypotheses(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[RankedHypothesisResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.get_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return [
        RankedHypothesisResponse(
            id=h.id,
            title=h.title,
            description=h.description,
            verdict=h.verdict.value,
            score=h.score,
            confidence=h.confidence,
            supporting_evidence_ids=h.supporting_evidence_ids,
            contradicting_evidence_ids=h.contradicting_evidence_ids,
            affected_file=h.affected_file,
            affected_symbol=h.affected_symbol,
            reasoning_summary=h.reasoning_summary,
            assumptions=h.assumptions,
            ranking_rationale=h.ranking_rationale,
            verification_steps=h.verification_steps,
        )
        for h in run.hypotheses
    ]


@router.get(
    "/analyses/{analysis_id}/verification-plan",
    response_model=list[VerificationStepResponse],
    summary="Retrieve verification steps for analysis",
)
async def get_analysis_verification_plan(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[VerificationStepResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.get_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return [
        VerificationStepResponse(
            id=v.id,
            hypothesis_id=v.hypothesis_id,
            action_type=v.action_type,
            target=v.target,
            command_preview=v.command_preview,
            is_executable=v.is_executable,
            expected_outcome=v.expected_outcome,
            actual_outcome=v.actual_outcome,
            status=v.status.value,
            duration_ms=v.duration_ms,
            notes=v.notes,
        )
        for v in run.verification_plan
    ]


@router.get(
    "/analyses/{analysis_id}/fixes",
    response_model=list[FixProposalResponse],
    summary="Retrieve minimal patch proposals for analysis",
)
async def get_analysis_fixes(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[FixProposalResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.get_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return [
        FixProposalResponse(
            id=p.id,
            hypothesis_id=p.hypothesis_id,
            target_file=p.target_file,
            target_symbol=p.target_symbol,
            defect_explanation=p.defect_explanation,
            diff_patch=p.diff_patch,
            expected_behavior=p.expected_behavior,
            recommended_tests=p.recommended_tests,
            validation_status=p.validation_status.value,
            validation_notes=p.validation_notes,
            safety_considerations=p.safety_considerations,
            confidence=p.confidence,
        )
        for p in run.fix_proposals
    ]


@router.post(
    "/analyses/{analysis_id}/cancel",
    response_model=DebuggingAnalysisResponse,
    summary="Cancel an active debugging analysis run",
)
async def cancel_analysis_run(
    analysis_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> DebuggingAnalysisResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    ev_service = EvidenceGraphService(session)
    debug_service = AutonomousDebuggingService(ev_service)

    run = await debug_service.cancel_analysis_run(organization_id=org_id, analysis_id=analysis_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    return _map_to_analysis_response(run)
