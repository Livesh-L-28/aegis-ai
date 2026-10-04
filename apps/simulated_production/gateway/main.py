import os
from uuid import uuid4

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from packages.logging.logger import get_logger
from packages.service_runtime.base import create_simulated_service

logger = get_logger("service.gateway")
app = create_simulated_service(service_name="gateway", version="1.0.0")

ORDER_SERVICE_URL = os.getenv("ORDER_SERVICE_URL", "http://order-service:8000")
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://user-service:8001")


class GatewayOrderRequest(BaseModel):
    user_id: str
    items: list[str]
    total_amount: float


@app.post("/api/orders")
async def create_order_proxy(payload: GatewayOrderRequest, request: Request) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid4()))
    headers = {"X-Request-ID": request_id}

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            res = await client.post(
                f"{ORDER_SERVICE_URL}/orders",
                json=payload.model_dump(),
                headers=headers,
            )
            return JSONResponse(status_code=res.status_code, content=res.json(), headers=headers)
        except httpx.TimeoutException:
            logger.error("Gateway timeout waiting for order-service")
            return JSONResponse(
                status_code=504,
                content={"error": {"code": "GATEWAY_TIMEOUT", "message": "Order service timed out"}},
                headers=headers,
            )
        except httpx.RequestError as exc:
            logger.error("Gateway error calling order-service: %s", exc)
            return JSONResponse(
                status_code=502,
                content={"error": {"code": "BAD_GATEWAY", "message": "Failed to connect to order-service"}},
                headers=headers,
            )


@app.get("/api/users/{user_id}")
async def get_user_proxy(user_id: str, request: Request) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid4()))
    headers = {"X-Request-ID": request_id}

    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            res = await client.get(f"{USER_SERVICE_URL}/users/{user_id}", headers=headers)
            return JSONResponse(status_code=res.status_code, content=res.json(), headers=headers)
        except httpx.RequestError:
            return JSONResponse(
                status_code=502,
                content={"error": {"code": "BAD_GATEWAY", "message": "Failed to connect to user-service"}},
                headers=headers,
            )
