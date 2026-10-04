import time

import pytest
from httpx import ASGITransport, AsyncClient

from apps.simulated_production.order_service.main import app as order_app
from apps.simulated_production.order_service.main import set_inter_service_clients
from apps.simulated_production.payment_service.main import app as payment_app
from apps.simulated_production.user_service.main import app as user_app
from packages.simulation.scenarios import simulation_registry


@pytest.mark.asyncio
async def test_canonical_database_latency_incident_flow() -> None:
    """CANONICAL END-TO-END BENCHMARK TEST (Section 38):

    1. Start normal system -> verify baseline latency & errors
    2. Activate database latency scenario (INC-001)
    3. Generate order traffic -> verify DB query duration increases, order duration increases
    4. Deactivate scenario -> verify system recovers to baseline
    """
    user_client = AsyncClient(transport=ASGITransport(app=user_app), base_url="http://user-service")
    payment_client = AsyncClient(transport=ASGITransport(app=payment_app), base_url="http://payment-service")
    set_inter_service_clients(user_client=user_client, payment_client=payment_client)

    try:
        async with AsyncClient(transport=ASGITransport(app=order_app), base_url="http://order-service") as oc:
            # 1. Normal baseline order request
            t0 = time.perf_counter()
            res_normal = await oc.post(
                "/orders",
                json={"user_id": "usr_101", "items": ["sku_item_1"], "total_amount": 100.0},
            )
            baseline_duration = time.perf_counter() - t0
            assert res_normal.status_code == 200
            assert res_normal.json()["status"] == "confirmed"
            assert baseline_duration < 0.2

            # 2. Activate INC-001: DB Latency (+250ms)
            scenario = simulation_registry.get("INC-001")
            assert scenario is not None
            scenario.parameters["latency_ms"] = 250
            simulation_registry.activate("INC-001")

            # 3. Generate order traffic under injected fault
            t1 = time.perf_counter()
            res_fault = await oc.post(
                "/orders",
                json={"user_id": "usr_101", "items": ["sku_item_2"], "total_amount": 250.0},
            )
            fault_duration = time.perf_counter() - t1
            assert res_fault.status_code == 200
            assert res_fault.json()["status"] == "confirmed"
            # Latency MUST exceed injected latency
            assert fault_duration >= 0.25

            # 4. Deactivate scenario and verify system recovery
            simulation_registry.deactivate("INC-001")

            t2 = time.perf_counter()
            res_recovered = await oc.post(
                "/orders",
                json={"user_id": "usr_101", "items": ["sku_item_3"], "total_amount": 50.0},
            )
            recovered_duration = time.perf_counter() - t2
            assert res_recovered.status_code == 200
            assert recovered_duration < 0.15
    finally:
        set_inter_service_clients(None, None)
        await user_client.aclose()
        await payment_client.aclose()
