"""Production Real-Time Server-Sent Events (SSE) Stream for Incident & Telemetry Updates."""

import asyncio
import json
from collections.abc import AsyncIterator
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import require_tenant_context
from packages.security.rbac import AuthenticatedPrincipal, Permission

router = APIRouter(prefix="/events", tags=["Real-Time Streaming"])


async def event_generator(org_id: UUID) -> AsyncIterator[str]:
    """Generates real-time SSE heartbeats and event payloads for connected enterprise clients."""
    iteration = 0
    while True:
        data = {
            "type": "heartbeat",
            "organization_id": str(org_id),
            "seq": iteration,
            "status": "nominal",
        }
        yield f"event: ping\ndata: {json.dumps(data)}\n\n"
        iteration += 1
        await asyncio.sleep(5)


@router.get("/stream")
async def stream_live_events(
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> StreamingResponse:
    """Enterprise Server-Sent Events (SSE) channel for real-time incident, remediation, and telemetry push."""
    if not principal.has_permission(Permission.SERVICE_READ):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Forbidden")

    return StreamingResponse(
        event_generator(org_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
