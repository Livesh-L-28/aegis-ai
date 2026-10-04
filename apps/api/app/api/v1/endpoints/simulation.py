from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_audit_service,
    get_request_id,
    require_tenant_context,
)
from apps.api.app.services.tenant import AuditService
from packages.security.rbac import AuthenticatedPrincipal, Permission
from packages.simulation.deployments import (
    DeploymentEvent,
    DeploymentStatus,
    deployment_registry,
)
from packages.simulation.scenarios import (
    FaultScenario,
    simulation_registry,
)

router = APIRouter(prefix="/simulation", tags=["Simulation & Fault Injection"])


class TriggerDeploymentRequest(BaseModel):
    service_name: str
    target_version: str
    previous_version: str | None = None
    induce_regression: bool = False


@router.get("/scenarios", response_model=list[FaultScenario])
async def list_scenarios(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[FaultScenario]:
    """List all registered canonical fault scenarios."""
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    return simulation_registry.list_all()


@router.get("/scenarios/{scenario_id}", response_model=FaultScenario)
async def get_scenario(
    scenario_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> FaultScenario:
    """Inspect specific fault scenario configuration and status."""
    scenario = simulation_registry.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return scenario


@router.post("/scenarios/{scenario_id}/activate", response_model=FaultScenario)
async def activate_scenario(
    scenario_id: str,
    org_id: Any = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    request_id: str = Depends(get_request_id),
) -> FaultScenario:
    """Activate a controlled failure scenario (Requires ADMIN or OWNER permissions)."""
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Insufficient privileges to trigger fault scenarios")

    try:
        scenario = simulation_registry.activate(scenario_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found") from err

    # Safety boundary auditing
    await audit_service.log_event(
        organization_id=org_id,
        actor_user_id=principal.user_id,
        action="simulation.scenario.activated",
        resource_type="scenario",
        resource_id=scenario_id,
        request_id=request_id,
        metadata={
            "scenario_name": scenario.name,
            "target_service": scenario.target_service,
            "fault_type": scenario.fault_type.value,
        },
    )
    return scenario


@router.post("/scenarios/{scenario_id}/deactivate", response_model=FaultScenario)
async def deactivate_scenario(
    scenario_id: str,
    org_id: Any = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    request_id: str = Depends(get_request_id),
) -> FaultScenario:
    """Deactivate a fault scenario to return environment to normal baseline."""
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Insufficient privileges to deactivate fault scenarios")

    try:
        scenario = simulation_registry.deactivate(scenario_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found") from err

    await audit_service.log_event(
        organization_id=org_id,
        actor_user_id=principal.user_id,
        action="simulation.scenario.deactivated",
        resource_type="scenario",
        resource_id=scenario_id,
        request_id=request_id,
        metadata={"scenario_name": scenario.name},
    )
    return scenario


@router.post("/deployments", response_model=DeploymentEvent, status_code=status.HTTP_201_CREATED)
async def trigger_deployment(
    payload: TriggerDeploymentRequest,
    org_id: Any = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    request_id: str = Depends(get_request_id),
) -> DeploymentEvent:
    """Simulate a release deployment event with optional regression trigger."""
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Insufficient privileges to trigger deployments")

    event = DeploymentEvent(
        service_name=payload.service_name,
        version=payload.target_version,
        previous_version=payload.previous_version,
        status=DeploymentStatus.COMPLETED,
        metadata={"induce_regression": payload.induce_regression},
    )
    recorded = deployment_registry.record(event)

    if payload.induce_regression:
        simulation_registry.activate("INC-005")

    await audit_service.log_event(
        organization_id=org_id,
        actor_user_id=principal.user_id,
        action="simulation.deployment.completed",
        resource_type="deployment",
        resource_id=str(recorded.deployment_id),
        request_id=request_id,
        metadata={"service": payload.service_name, "version": payload.target_version},
    )
    return recorded
