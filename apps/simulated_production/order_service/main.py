import asyncio
import os
import time
from uuid import uuid4

import httpx
from fastapi import HTTPException, Request
from pydantic import BaseModel

from packages.logging.logger import get_logger
from packages.service_runtime.base import create_simulated_service
from packages.service_runtime.metrics import (
    DATABASE_QUERY_DURATION_SECONDS,
    ORDERS_CREATED_TOTAL,
    ORDERS_FAILED_TOTAL,
)
from packages.simulation.scenarios import FaultType, simulation_registry

logger = get_logger("service.order-service")
app = create_simulated_service(service_name="order-service", version="1.0.0")

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://user-service:8001")
PAYMENT_SERVICE_URL = os.getenv("PAYMENT_SERVICE_URL", "http://payment-service:8002")

# Pluggable clients for testing / in-process execution
_user_client: httpx.AsyncClient | None = None
_payment_client: httpx.AsyncClient | None = None


def set_inter_service_clients(
    user_client: httpx.AsyncClient | None = None,
    payment_client: httpx.AsyncClient | None = None,
) -> None:
    global _user_client, _payment_client
    _user_client = user_client
    _payment_client = payment_client

# Internal simulated orders database
ORDERS: dict[str, dict] = {}


class CreateOrderRequest(BaseModel):
    user_id: str
    items: list[str]
    total_amount: float


class OrderResponse(BaseModel):
    order_id: str
    user_id: str
    status: str
    total_amount: float
    payment_id: str | None = None


@app.post("/orders", response_model=OrderResponse)
async def create_order(payload: CreateOrderRequest, request: Request) -> OrderResponse:
    request_id = getattr(request.state, "request_id", str(uuid4()))
    getattr(request.state, "trace_id", None)
    headers = {"X-Request-ID": request_id}

    # 1. Check for Deployment Regression fault (INC-005)
    deploy_fault = simulation_registry.is_fault_active("order-service", FaultType.DEPLOYMENT_REGRESSION)
    if deploy_fault:
        ORDERS_FAILED_TOTAL.labels(service="order-service", reason="deployment_regression").inc()
        logger.error("FAULT ACTIVE [INC-005]: Unhandled null-pointer regression in Order Service v1.1.0")
        raise HTTPException(status_code=500, detail="Unhandled Order Processing Engine Regression")

    # 2. Call user-service to validate customer
    try:
        if _user_client is not None:
            user_res = await _user_client.get(f"/users/{payload.user_id}", headers=headers)
        else:
            async with httpx.AsyncClient(timeout=3.0) as client:
                user_res = await client.get(f"{USER_SERVICE_URL}/users/{payload.user_id}", headers=headers)

        if user_res.status_code != 200:
            ORDERS_FAILED_TOTAL.labels(service="order-service", reason="user_invalid").inc()
            raise HTTPException(status_code=400, detail="Invalid user for order placement")
    except httpx.RequestError as exc:
        ORDERS_FAILED_TOTAL.labels(service="order-service", reason="user_service_unreachable").inc()
        logger.error("Failed to connect to user-service: %s", exc)
        raise HTTPException(status_code=503, detail="User verification unavailable") from exc

    order_id = str(uuid4())

    # 3. Call payment-service to charge order
    try:
        charge_payload = {
            "order_id": order_id,
            "amount": payload.total_amount,
            "user_id": payload.user_id,
        }
        if _payment_client is not None:
            pay_res = await _payment_client.post("/payments/charge", json=charge_payload, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=2.0) as client:
                pay_res = await client.post(
                    f"{PAYMENT_SERVICE_URL}/payments/charge",
                    json=charge_payload,
                    headers=headers,
                )

        if pay_res.status_code != 200:
            ORDERS_FAILED_TOTAL.labels(service="order-service", reason="payment_failed").inc()
            logger.error("Payment failed for order %s (status %s)", order_id, pay_res.status_code)
            raise HTTPException(status_code=502, detail=f"Payment processing failed: {pay_res.text}")
        payment_data = pay_res.json()
        payment_id = payment_data.get("payment_id")
    except httpx.TimeoutException as exc:
        ORDERS_FAILED_TOTAL.labels(service="order-service", reason="payment_timeout").inc()
        logger.error("Payment service timed out for order %s", order_id)
        raise HTTPException(status_code=504, detail="Upstream payment service timed out") from exc
    except httpx.RequestError as exc:
        ORDERS_FAILED_TOTAL.labels(service="order-service", reason="payment_service_unreachable").inc()
        logger.error("Failed to communicate with payment-service: %s", exc)
        raise HTTPException(status_code=503, detail="Payment gateway unavailable") from exc

    # 4. Persist order into simulated PostgreSQL
    db_start = time.perf_counter()
    # Check for Database Latency fault (INC-001)
    db_latency_fault = simulation_registry.is_fault_active("order-service", FaultType.DATABASE_LATENCY)
    if db_latency_fault:
        delay_s = db_latency_fault.parameters.get("latency_ms", 1500) / 1000.0
        logger.warning("FAULT ACTIVE [INC-001]: Injecting %0.2fs database latency", delay_s)
        await asyncio.sleep(delay_s)

    db_duration = time.perf_counter() - db_start
    DATABASE_QUERY_DURATION_SECONDS.labels(service="order-service", operation="INSERT").observe(db_duration)

    order_record = {
        "order_id": order_id,
        "user_id": payload.user_id,
        "status": "confirmed",
        "total_amount": payload.total_amount,
        "payment_id": payment_id,
    }
    ORDERS[order_id] = order_record
    ORDERS_CREATED_TOTAL.labels(service="order-service").inc()

    logger.info("Order %s created successfully", order_id, extra={"order_id": order_id, "request_id": request_id})
    return OrderResponse(**order_record)


@app.get("/orders/{order_id}", response_model=OrderResponse)
async def get_order(order_id: str) -> OrderResponse:
    if order_id not in ORDERS:
        raise HTTPException(status_code=404, detail="Order not found")
    return OrderResponse(**ORDERS[order_id])
