from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.dependencies.core import (
    get_db_session,
    require_tenant_context,
)
from apps.api.app.models.entities import AIPolicy, AIUsageRecord
from apps.api.app.schemas.domain import (
    AIComponentHealth,
    AIHealthResponse,
    AIModelMetadataResponse,
    AIPolicyResponse,
    AIProviderResponse,
    AIReliabilityResponse,
    AIUsageRecordResponse,
    FirewallStatusResponse,
)
from packages.intelligence.reasoning.reliability import (
    AIReliabilityService,
    default_reliability_service,
)
from packages.intelligence.reasoning.router import ModelRouter
from packages.security.llm_firewall.adapter import LLMFirewallCoreAdapter
from packages.security.policy import AIPolicyEngine

router = APIRouter(prefix="/ai", tags=["AI Trust & Reliability"])


@router.get("/models", response_model=list[AIModelMetadataResponse])
async def list_models(
    router_engine: ModelRouter = Depends(ModelRouter.get_default_router),
) -> list[AIModelMetadataResponse]:
    """List registered AI models and capabilities."""
    registered = router_engine.list_models()
    return [
        AIModelMetadataResponse(
            name=m.model,
            provider=m.provider,
            version=m.version,
            capabilities=[c.value for c in m.capabilities],
            context_limit=m.context_limit,
            enabled=m.enabled,
            priority=m.priority,
            cost_per_1k_input_tokens=m.input_cost_per_1k,
            cost_per_1k_output_tokens=m.output_cost_per_1k,
        )
        for m in registered
    ]



@router.get("/providers", response_model=list[AIProviderResponse])
async def list_providers(
    router_engine: ModelRouter = Depends(ModelRouter.get_default_router),
) -> list[AIProviderResponse]:
    """List AI model providers and circuit breaker states."""
    providers = router_engine.list_providers()
    res: list[AIProviderResponse] = []
    for p in providers:
        cb = router_engine.circuit_breakers.get(p.provider_name)
        status_val = (await p.health()).value if hasattr(p, "health") else "healthy"
        res.append(
            AIProviderResponse(
                name=p.provider_name,
                status=status_val,
                capabilities=[c.value for c in p.capabilities()],
                circuit_state=cb.state.value if cb else "CLOSED",
                failure_count=cb.failure_count if cb else 0,
                models=[m.model for m in router_engine.list_models() if m.provider == p.provider_name],
            )
        )
    return res



@router.get("/health", response_model=AIHealthResponse)
async def get_ai_health(
    router_engine: ModelRouter = Depends(ModelRouter.get_default_router),
) -> AIHealthResponse:
    """Multi-dimensional AI health check across API, Firewall, Policy Engine, Router, and Grounding."""
    firewall = LLMFirewallCoreAdapter()
    fw_status = firewall.health_status()
    fw_healthy = fw_status.get("healthy", False)

    policy_engine = AIPolicyEngine()

    providers = router_engine.list_providers()
    healthy_prov_names: list[str] = []
    for p in providers:
        h = await p.health()
        if h.value == "healthy":
            healthy_prov_names.append(p.provider_name)

    router_healthy = len(healthy_prov_names) > 0


    rel_status = default_reliability_service.health_status()
    rel_healthy = rel_status.get("healthy", False)

    overall_status = "healthy"
    if not fw_healthy or not router_healthy or not rel_healthy:
        overall_status = "degraded" if (fw_healthy or router_healthy) else "unhealthy"

    return AIHealthResponse(
        status=overall_status,
        api=AIComponentHealth(status="healthy", details={"version": "1.0.0"}),
        firewall=AIComponentHealth(
            status="healthy" if fw_healthy else "degraded",
            details=fw_status,
        ),
        policy_engine=AIComponentHealth(
            status="healthy",
            details={"policy_version": policy_engine.policy_version},
        ),
        model_router=AIComponentHealth(
            status="healthy" if router_healthy else "unhealthy",
            details={"healthy_providers": healthy_prov_names},
        ),
        grounding_validator=AIComponentHealth(
            status="healthy",
            details={"mode": "deterministic_evidence_verification"},
        ),
        reliability_engine=AIComponentHealth(
            status="healthy" if rel_healthy else "degraded",
            details=rel_status,
        ),
    )



@router.get("/reliability", response_model=AIReliabilityResponse)
async def get_ai_reliability(
    org_id: UUID = Depends(require_tenant_context),
    service: AIReliabilityService = Depends(AIReliabilityService.get_default_service),
) -> AIReliabilityResponse:
    """Get tenant-scoped AI reliability metrics and transparent composite score."""
    summary = service.get_summary(organization_id=org_id)
    return AIReliabilityResponse(
        total_requests=summary.total_requests,
        successful_requests=summary.successful_requests,
        failed_requests=summary.failed_requests,
        availability_rate=summary.availability_rate,
        grounding_rate=summary.grounding_rate,
        safety_rate=summary.safety_rate,
        reliability_score=summary.reliability_score,
        avg_latency_ms=summary.avg_latency_ms,
        total_input_tokens=summary.total_input_tokens,
        total_output_tokens=summary.total_output_tokens,
        total_cost_usd=summary.total_cost_usd,
        hallucination_indicators=summary.hallucination_indicators,
        score_breakdown=summary.score_breakdown,
    )


@router.get("/usage", response_model=list[AIUsageRecordResponse])
async def list_ai_usage(
    limit: int = Query(50, ge=1, le=200),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
) -> list[AIUsageRecordResponse]:
    """List tenant-isolated AI token usage and cost records."""
    stmt = (
        select(AIUsageRecord)
        .where(AIUsageRecord.organization_id == org_id)
        .order_by(AIUsageRecord.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    records = result.scalars().all()
    return [AIUsageRecordResponse.model_validate(r) for r in records]


@router.get("/policies", response_model=list[AIPolicyResponse])
async def list_ai_policies(
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
) -> list[AIPolicyResponse]:
    """List tenant-scoped programmatic AI policies."""
    stmt = (
        select(AIPolicy)
        .where(AIPolicy.organization_id == org_id)
        .order_by(AIPolicy.created_at.desc())
    )
    result = await session.execute(stmt)
    policies = result.scalars().all()
    return [AIPolicyResponse.model_validate(p) for p in policies]



@router.get("/firewall/status", response_model=FirewallStatusResponse)
async def get_firewall_status() -> FirewallStatusResponse:
    """Get operational status of the LLM Firewall without leaking internal rules or secrets."""
    firewall = LLMFirewallCoreAdapter()
    info = firewall.health_status()
    return FirewallStatusResponse(
        enabled=info.get("enabled", True),
        healthy=info.get("healthy", False),
        version=info.get("version", "1.0.0"),
        policy_version=info.get("policy_version", "default-v1"),
    )
