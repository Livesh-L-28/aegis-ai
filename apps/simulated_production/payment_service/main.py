import asyncio
import time

from fastapi import HTTPException
from pydantic import BaseModel

from packages.logging.logger import get_logger
from packages.service_runtime.base import create_simulated_service
from packages.service_runtime.metrics import (
    PAYMENTS_ATTEMPTED_TOTAL,
    PAYMENTS_FAILED_TOTAL,
    REDIS_ERRORS_TOTAL,
    REDIS_OPERATION_DURATION_SECONDS,
)
from packages.simulation.scenarios import FaultType, simulation_registry

logger = get_logger("service.payment-service")
app = create_simulated_service(service_name="payment-service", version="1.0.0")


class ProcessPaymentRequest(BaseModel):
    order_id: str
    amount: float
    currency: str = "USD"
    user_id: str


class ProcessPaymentResponse(BaseModel):
    payment_id: str
    order_id: str
    status: str
    amount: float


@app.post("/payments/charge", response_model=ProcessPaymentResponse)
async def process_payment(payload: ProcessPaymentRequest) -> ProcessPaymentResponse:
    PAYMENTS_ATTEMPTED_TOTAL.labels(service="payment-service").inc()

    # 1. Check for Service Latency fault (INC-003)
    latency_fault = simulation_registry.is_fault_active("payment-service", FaultType.SERVICE_LATENCY)
    if latency_fault:
        delay_s = latency_fault.parameters.get("latency_ms", 3000) / 1000.0
        logger.warning("FAULT ACTIVE [INC-003]: Injecting %0.2fs latency", delay_s)
        await asyncio.sleep(delay_s)

    # 2. Check for Service Error Rate fault (INC-004)
    error_fault = simulation_registry.is_fault_active("payment-service", FaultType.SERVICE_ERROR_RATE)
    if error_fault:
        PAYMENTS_FAILED_TOTAL.labels(service="payment-service", reason="simulated_500_surge").inc()
        logger.error("FAULT ACTIVE [INC-004]: Forcing HTTP 500 error on payment charge")
        raise HTTPException(status_code=500, detail="Simulated payment processing internal error")

    # 3. Check for Redis Failure fault (INC-002)
    redis_fault = simulation_registry.is_fault_active("payment-service", FaultType.REDIS_FAILURE)
    redis_start = time.perf_counter()
    if redis_fault:
        REDIS_ERRORS_TOTAL.labels(service="payment-service", command="SETEX").inc()
        PAYMENTS_FAILED_TOTAL.labels(service="payment-service", reason="redis_unreachable").inc()
        logger.error("FAULT ACTIVE [INC-002]: Redis connection failed during idempotency verification")
        raise HTTPException(status_code=503, detail="Payment ledger cache unreachable (Redis connection error)")

    # Normal simulated Redis idempotency reservation
    redis_duration = time.perf_counter() - redis_start
    REDIS_OPERATION_DURATION_SECONDS.labels(service="payment-service", command="SETEX").observe(redis_duration)

    payment_id = f"pay_{payload.order_id[:8]}_{int(time.time())}"
    logger.info("Payment %s processed successfully for order %s", payment_id, payload.order_id)
    return ProcessPaymentResponse(
        payment_id=payment_id,
        order_id=payload.order_id,
        status="succeeded",
        amount=payload.amount,
    )
