from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from apps.api.app.core.security import get_current_principal
from packages.security.rbac import AuthenticatedPrincipal, Permission
from packages.simulation.deployments import DeploymentEvent, deployment_registry

router = APIRouter(prefix="/observability", tags=["Observability & Telemetry"])


class ServiceTelemetrySummary(BaseModel):
    service: str
    environment: str
    version: str
    status: str
    endpoint: str


class MetricsSummaryResponse(BaseModel):
    sample_timestamp: str
    services_reporting: int
    active_incidents_simulated: int


@router.get("/services", response_model=list[ServiceTelemetrySummary])
async def list_observable_services(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[ServiceTelemetrySummary]:
    """Retrieve metadata of all observable services registered in the simulated production topology."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")

    return [
        ServiceTelemetrySummary(
            service="gateway",
            environment="production-sim",
            version="1.0.0",
            status="healthy",
            endpoint="http://gateway:8080",
        ),
        ServiceTelemetrySummary(
            service="order-service",
            environment="production-sim",
            version="1.0.0",
            status="healthy",
            endpoint="http://order-service:8000",
        ),
        ServiceTelemetrySummary(
            service="payment-service",
            environment="production-sim",
            version="1.0.0",
            status="healthy",
            endpoint="http://payment-service:8002",
        ),
        ServiceTelemetrySummary(
            service="user-service",
            environment="production-sim",
            version="1.0.0",
            status="healthy",
            endpoint="http://user-service:8001",
        ),
    ]


@router.get("/services/{service_name}", response_model=ServiceTelemetrySummary)
async def get_observable_service(
    service_name: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ServiceTelemetrySummary:
    """Retrieve specific service observability metadata."""
    services = await list_observable_services(principal)
    for s in services:
        if s.service == service_name:
            return s
    raise HTTPException(status_code=404, detail=f"Service '{service_name}' not found")


@router.get("/deployments", response_model=list[DeploymentEvent])
async def list_deployment_history(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[DeploymentEvent]:
    """Query service deployment events history for timeline correlation."""
    if not principal.has_permission(Permission.SERVICE_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    return deployment_registry.list_all()
