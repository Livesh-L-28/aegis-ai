from uuid import UUID

from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.config import settings
from apps.api.app.core.exceptions import TenantViolationException
from apps.api.app.core.security import get_current_principal
from apps.api.app.db.session import get_db_session
from apps.api.app.services.health import HealthService
from apps.api.app.services.infrastructure import (
    RedisService,
    get_object_storage,
    get_redis_service,
)
from apps.api.app.services.tenant import (
    AuditService,
    OrganizationService,
    ProjectService,
)
from packages.common.storage import ObjectStorage
from packages.security.rbac import AuthenticatedPrincipal


async def get_request_id(request: Request) -> str:
    """Dependency to extract correlation/request ID."""
    return getattr(request.state, "request_id", "req_unknown")


async def get_audit_service(
    session: AsyncSession = Depends(get_db_session),
) -> AuditService:
    return AuditService(session)


async def get_org_service(
    session: AsyncSession = Depends(get_db_session),
    audit_service: AuditService = Depends(get_audit_service),
) -> OrganizationService:
    return OrganizationService(session, audit_service)


async def get_project_service(
    session: AsyncSession = Depends(get_db_session),
    audit_service: AuditService = Depends(get_audit_service),
) -> ProjectService:
    return ProjectService(session, audit_service)


async def get_redis() -> RedisService:
    return get_redis_service(settings)


async def get_storage() -> ObjectStorage:
    return get_object_storage(settings)


async def get_health_service(
    session: AsyncSession = Depends(get_db_session),
    redis: RedisService = Depends(get_redis),
    storage: ObjectStorage = Depends(get_storage),
) -> HealthService:
    return HealthService(session, redis, storage)


async def require_tenant_context(
    x_organization_id: str | None = Header(None),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> UUID:
    """Strict dependency ensuring a valid Organization tenant context is present and authorized."""
    if not x_organization_id:
        raise TenantViolationException("X-Organization-ID header is required for tenant operations")

    try:
        org_uuid = UUID(x_organization_id)
    except ValueError as err:
        raise TenantViolationException("Invalid X-Organization-ID format; must be UUID") from err

    # If principal has explicit organization restriction, enforce match
    if principal.current_organization_id and str(principal.current_organization_id) != str(org_uuid):
        raise TenantViolationException("Principal is not authorized to access this organization tenant")

    return org_uuid
