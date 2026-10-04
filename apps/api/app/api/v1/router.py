from fastapi import APIRouter

from apps.api.app.api.v1.endpoints import (
    ai,
    audit,
    autonomy,
    events,
    health,
    intelligence,
    investigations,
    observability,
    onboarding,
    organizations,
    projects,
    remediations,
    simulation,
)

v1_router = APIRouter()

# Client Onboarding (1-Click Connect)
v1_router.include_router(onboarding.router)

# System Endpoints
v1_router.include_router(health.router)
v1_router.include_router(events.router)

# Domain & Tenant Endpoints
v1_router.include_router(organizations.router)
v1_router.include_router(projects.router)
v1_router.include_router(audit.router)

# Phase 2 Simulation & Observability Endpoints
v1_router.include_router(simulation.router)
v1_router.include_router(observability.router)

# Phase 3 Intelligence Endpoints
v1_router.include_router(intelligence.router)

# Phase 4 Incidents & Investigations Endpoints
v1_router.include_router(investigations.router)

# Phase 5 AI Trust & Reliability Endpoints
v1_router.include_router(ai.router)

# Phase 6 AI Remediation & Deployment Endpoints
v1_router.include_router(remediations.router)

# Phase 7 Autonomous Reliability & Evaluation Endpoints
v1_router.include_router(autonomy.router)



