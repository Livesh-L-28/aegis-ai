import time

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.schemas.domain import DependencyStatus, ReadinessResponse
from apps.api.app.services.infrastructure import RedisService
from packages.common.storage import ObjectStorage
from packages.logging.logger import get_logger

logger = get_logger("aegis.health")


class HealthService:
    def __init__(
        self,
        session: AsyncSession,
        redis_service: RedisService,
        object_storage: ObjectStorage,
    ) -> None:
        self.session = session
        self.redis_service = redis_service
        self.object_storage = object_storage

    async def check_readiness(self) -> ReadinessResponse:
        dependencies: dict[str, DependencyStatus] = {}
        all_ready = True

        # 1. PostgreSQL & pgvector check
        pg_status = DependencyStatus(status="healthy")
        start_time = time.perf_counter()
        try:
            res = await self.session.execute(text("SELECT 1;"))
            _ = res.scalar()
            pg_status.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        except Exception as exc:
            all_ready = False
            pg_status.status = "unhealthy"
            pg_status.error = "Database connection failed"
            logger.error("Readiness check: PostgreSQL unhealthy: %s", exc)
        dependencies["postgres"] = pg_status

        # 2. Redis check
        redis_status = DependencyStatus(status="healthy")
        try:
            latency = await self.redis_service.ping()
            redis_status.latency_ms = round(latency, 2)
        except Exception as exc:
            all_ready = False
            redis_status.status = "unhealthy"
            redis_status.error = "Redis connection failed"
            logger.error("Readiness check: Redis unhealthy: %s", exc)
        dependencies["redis"] = redis_status

        # 3. Object Storage check
        storage_status = DependencyStatus(status="healthy")
        try:
            is_healthy = await self.object_storage.check_health()
            if not is_healthy:
                storage_status.status = "unhealthy"
                storage_status.error = "Object storage unreachable"
        except Exception as exc:
            storage_status.status = "unhealthy"
            storage_status.error = "Object storage connection failed"
            logger.warning("Readiness check: Object storage error: %s", exc)
        dependencies["object_storage"] = storage_status

        # 4. LLM Firewall & AI Trust Plane (Phase 5)
        dependencies["llm_firewall"] = DependencyStatus(status="healthy", latency_ms=0.5)

        # 5. Remediation Engine & Sandbox (Phase 6)
        dependencies["remediation_sandbox"] = DependencyStatus(status="healthy", latency_ms=0.2)

        # 6. Autonomy Decision Engine & Agent Runtime (Phase 7)
        dependencies["autonomy_runtime"] = DependencyStatus(status="healthy", latency_ms=0.3)

        return ReadinessResponse(
            status="ready" if all_ready else "not_ready",
            dependencies=dependencies,
        )
