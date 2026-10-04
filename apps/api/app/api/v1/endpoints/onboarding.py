"""1-Click Client Product Connection & Instant Onboarding Endpoint."""

from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_audit_service,
    get_request_id,
    require_tenant_context,
)
from apps.api.app.services.tenant import AuditService
from packages.intelligence.system.registry import (
    DependencyType,
    ServiceDependency,
    system_registry,
)
from packages.security.rbac import AuthenticatedPrincipal, Permission

router = APIRouter(prefix="/onboarding", tags=["Client Onboarding"])


class ConnectProductRequest(BaseModel):
    product_name: str = Field(..., min_length=2, max_length=100)
    product_type: Literal["microservice", "ai_application", "api_gateway", "database"] = "microservice"
    endpoint_url: str | None = Field(default=None, max_length=500)
    environment: str = Field(default="production", max_length=50)
    probe_health: bool = Field(default=True)


class ConnectProductResponse(BaseModel):
    status: Literal["connected", "degraded", "pending"]
    product_id: str
    product_name: str
    product_type: str
    environment: str
    connection_token: str
    proxy_endpoint: str
    health_checked: bool
    message: str


@router.post("/connect", response_model=ConnectProductResponse, status_code=status.HTTP_201_CREATED)
async def connect_client_product(
    request: Request,
    payload: ConnectProductRequest,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    request_id: str = Depends(get_request_id),
) -> ConnectProductResponse:
    """Connect a client product or service to AEGIS in 1 click."""
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Forbidden")

    clean_name = payload.product_name.strip().lower().replace(" ", "-")
    node_id = f"node_{clean_name}_{str(org_id)[:8]}"
    health_verified = False
    conn_status: Literal["connected", "degraded", "pending"] = "connected"

    # Optional real-time HTTP health check
    if payload.probe_health and payload.endpoint_url:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(payload.endpoint_url)
                if res.status_code < 400:
                    health_verified = True
                else:
                    conn_status = "degraded"
        except Exception:
            # If endpoint isn't reached immediately, mark connected but unverified
            conn_status = "connected"

    # Register in runtime dependency topology mesh
    system_registry.add_dependency(
        ServiceDependency(
            organization_id=org_id,
            source_service_name="gateway",
            target_service_name=clean_name,
            dependency_type=DependencyType.EXTERNAL_API if payload.product_type == "api_gateway" else DependencyType.HTTP,
            protocol="HTTP/REST",
            metadata={
                "client_onboarded": True,
                "endpoint_url": payload.endpoint_url,
                "product_type": payload.product_type,
                "environment": payload.environment,
            },
        )
    )

    # Immutable Audit Log Entry
    await audit_service.log_event(
        organization_id=org_id,
        actor_user_id=principal.user_id,
        action="client.product.connected",
        resource_type="service",
        resource_id=node_id,
        request_id=request_id,
        metadata={
            "product_name": payload.product_name,
            "product_type": payload.product_type,
            "environment": payload.environment,
            "endpoint_url": payload.endpoint_url,
            "health_verified": health_verified,
        },
    )

    connection_token = f"aegis_sec_{clean_name}_{str(org_id)[:6]}"
    base_url = str(request.base_url).rstrip("/")
    proxy_endpoint = f"{base_url}/api/v1/ai/proxy?org={org_id}"

    return ConnectProductResponse(
        status=conn_status,
        product_id=node_id,
        product_name=payload.product_name,
        product_type=payload.product_type,
        environment=payload.environment,
        connection_token=connection_token,
        proxy_endpoint=proxy_endpoint,
        health_checked=health_verified,
        message=f"Product '{payload.product_name}' successfully connected to AEGIS Reliability Mesh.",
    )
