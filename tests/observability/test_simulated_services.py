import pytest
from httpx import ASGITransport, AsyncClient

from apps.simulated_production.gateway.main import app as gateway_app
from apps.simulated_production.order_service.main import app as order_app
from apps.simulated_production.payment_service.main import app as payment_app
from apps.simulated_production.user_service.main import app as user_app
from packages.simulation.scenarios import simulation_registry


@pytest.mark.asyncio
async def test_simulated_services_health_and_metadata() -> None:
    for service_name, app_instance in [
        ("gateway", gateway_app),
        ("order-service", order_app),
        ("payment-service", payment_app),
        ("user-service", user_app),
    ]:
        transport = ASGITransport(app=app_instance)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            health_res = await ac.get("/health")
            assert health_res.status_code == 200
            assert health_res.json()["status"] == "ok"
            assert health_res.json()["service"] == service_name

            meta_res = await ac.get("/metadata")
            assert meta_res.status_code == 200
            assert meta_res.json()["environment"] == "production-sim"
            assert "version" in meta_res.json()

            metrics_res = await ac.get("/metrics")
            assert metrics_res.status_code == 200
            assert "http_requests_total" in metrics_res.text


@pytest.mark.asyncio
async def test_payment_service_redis_failure_and_recovery() -> None:
    """End-to-End Test 2: INC-002 Redis Failure and Recovery."""
    transport = ASGITransport(app=payment_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Normal payment operation
        normal_res = await ac.post(
            "/payments/charge",
            json={"order_id": "ord_1001", "amount": 99.0, "user_id": "usr_101"},
        )
        assert normal_res.status_code == 200
        assert normal_res.json()["status"] == "succeeded"

        # 2. Activate INC-002 Redis Failure fault
        simulation_registry.activate("INC-002")

        # 3. Process payment during failure -> Must fail with 503 (Redis connection error)
        fail_res = await ac.post(
            "/payments/charge",
            json={"order_id": "ord_1002", "amount": 49.0, "user_id": "usr_101"},
        )
        assert fail_res.status_code == 503
        assert "Redis connection error" in fail_res.json()["detail"]

        # Check metrics updated
        metrics_res = await ac.get("/metrics")
        assert 'payments_failed_total{reason="redis_unreachable",service="payment-service"}' in metrics_res.text
        assert 'redis_errors_total{command="SETEX",service="payment-service"}' in metrics_res.text

        # 4. Deactivate scenario and verify recovery
        simulation_registry.deactivate("INC-002")

        recovery_res = await ac.post(
            "/payments/charge",
            json={"order_id": "ord_1003", "amount": 25.0, "user_id": "usr_101"},
        )
        assert recovery_res.status_code == 200
        assert recovery_res.json()["status"] == "succeeded"


@pytest.mark.asyncio
async def test_payment_service_error_rate_fault_inc_004() -> None:
    transport = ASGITransport(app=payment_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        simulation_registry.activate("INC-004")
        fail_res = await ac.post(
            "/payments/charge",
            json={"order_id": "ord_1004", "amount": 10.0, "user_id": "usr_101"},
        )
        assert fail_res.status_code == 500
        simulation_registry.deactivate("INC-004")

        rec_res = await ac.post(
            "/payments/charge",
            json={"order_id": "ord_1005", "amount": 10.0, "user_id": "usr_101"},
        )
        assert rec_res.status_code == 200
