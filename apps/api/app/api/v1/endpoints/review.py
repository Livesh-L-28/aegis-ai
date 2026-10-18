"""FastAPI router for Repository Intelligence & Code Review endpoints."""

from collections.abc import Sequence
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_db_session,
    require_tenant_context,
)
from apps.api.app.schemas.domain import (
    ReviewCancelRequest,
    ReviewCreateRequest,
    ReviewFindingResponse,
    ReviewSessionResponse,
)
from apps.api.app.services.review import CodeReviewService
from packages.review.github.webhook import GitHubWebhookVerifier, WebhookSecurityError
from packages.security.rbac import AuthenticatedPrincipal, Permission

router = APIRouter(prefix="/reviews", tags=["Repository Code Review"])


@router.post(
    "",
    response_model=ReviewSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new repository code review",
)
async def start_code_review(
    payload: ReviewCreateRequest,
    background_tasks: BackgroundTasks,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ReviewSessionResponse:
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Forbidden")

    service = CodeReviewService(session)
    review_session = await service.create_review_session(
        organization_id=org_id,
        payload=payload,
    )

    # Execute review in background task or immediately
    background_tasks.add_task(
        service.execute_review,
        session_id=review_session.id,
        organization_id=org_id,
        diff_text=payload.diff_text,
        enable_ai=payload.enable_ai,
    )

    return ReviewSessionResponse.model_validate(review_session)


@router.get(
    "/{review_id}",
    response_model=ReviewSessionResponse,
    summary="Retrieve status and summary for a review session",
)
async def get_code_review_status(
    review_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ReviewSessionResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    service = CodeReviewService(session)
    review_session = await service.get_session(review_id, org_id)
    if not review_session:
        raise HTTPException(status_code=404, detail="Review session not found")

    return ReviewSessionResponse.model_validate(review_session)


@router.get(
    "/{review_id}/findings",
    response_model=list[ReviewFindingResponse],
    summary="Retrieve paginated findings for a review session",
)
async def get_code_review_findings(
    review_id: UUID,
    severity: str | None = Query(None, description="Filter by severity (INFO, WARNING, ERROR, CRITICAL)"),
    category: str | None = Query(None, description="Filter by category (SECURITY, QUALITY, etc.)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> Sequence[ReviewFindingResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    service = CodeReviewService(session)
    # Check session existence first
    review_session = await service.get_session(review_id, org_id)
    if not review_session:
        raise HTTPException(status_code=404, detail="Review session not found")

    findings = await service.list_findings(
        session_id=review_id,
        organization_id=org_id,
        severity=severity,
        category=category,
        limit=limit,
        offset=offset,
    )
    return [ReviewFindingResponse.model_validate(f) for f in findings]


@router.post(
    "/{review_id}/cancel",
    response_model=ReviewSessionResponse,
    summary="Cancel an in-flight review session",
)
async def cancel_code_review(
    review_id: UUID,
    payload: ReviewCancelRequest,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ReviewSessionResponse:
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Forbidden")

    service = CodeReviewService(session)
    cancelled = await service.cancel_session(review_id, org_id, reason=payload.reason)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Review session not found")

    return ReviewSessionResponse.model_validate(cancelled)


@router.get(
    "",
    response_model=list[ReviewSessionResponse],
    summary="List review history for the authenticated tenant",
)
async def list_code_reviews(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> Sequence[ReviewSessionResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    service = CodeReviewService(session)
    sessions = await service.list_sessions(organization_id=org_id, limit=limit, offset=offset)
    return [ReviewSessionResponse.model_validate(s) for s in sessions]


@router.post(
    "/github/webhook",
    status_code=status.HTTP_200_OK,
    summary="Handle GitHub pull request webhooks with signature verification",
)
async def handle_github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
    x_github_delivery: str | None = Header(None),
) -> dict[str, str]:
    body_bytes = await request.body()
    try:
        verifier = GitHubWebhookVerifier()
    except WebhookSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook security configuration error: {e}",
        ) from e

    if not verifier.verify_signature(payload=body_bytes, signature_header=x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook HMAC signature")

    if x_github_event != "pull_request":
        return {"status": "ignored", "reason": f"Event '{x_github_event}' not monitored"}

    return {"status": "accepted", "delivery_id": x_github_delivery or "unknown"}
