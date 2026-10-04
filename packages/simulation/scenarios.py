from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FaultType(StrEnum):
    DATABASE_LATENCY = "database_latency"
    DATABASE_CONNECTION_EXHAUSTION = "database_connection_exhaustion"
    REDIS_FAILURE = "redis_failure"
    SERVICE_LATENCY = "service_latency"
    SERVICE_ERROR_RATE = "service_error_rate"
    DEPENDENCY_TIMEOUT = "dependency_timeout"
    DEPLOYMENT_REGRESSION = "deployment_regression"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FaultScenario(BaseModel):
    id: str
    name: str
    description: str
    fault_type: FaultType
    target_service: str  # e.g., "order-service", "payment-service"
    risk_level: RiskLevel = RiskLevel.MEDIUM
    enabled: bool = False
    duration_seconds: int = 300
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_telemetry: str = ""
    expected_impact: str = ""


class ScenarioRegistry:
    """In-memory thread-safe state registry for active simulation scenarios."""

    def __init__(self) -> None:
        self._scenarios: dict[str, FaultScenario] = {}
        self._initialize_canonical_benchmarks()

    def _initialize_canonical_benchmarks(self) -> None:
        canonical = [
            FaultScenario(
                id="INC-001",
                name="PostgreSQL Query Latency Spike",
                description="Injects +1500ms query latency into Order Service database access, inducing order processing delays and HTTP timeouts.",
                fault_type=FaultType.DATABASE_LATENCY,
                target_service="order-service",
                risk_level=RiskLevel.MEDIUM,
                parameters={"latency_ms": 1500},
                expected_telemetry="database_query_duration_seconds spikes, http_request_duration_seconds increases for POST /orders",
                expected_impact="Elevated order transaction latency and cascading gateway timeouts",
            ),
            FaultScenario(
                id="INC-002",
                name="Redis Ephemeral Dependency Failure",
                description="Simulates Redis connection breakdown in Payment Service, causing ledger cache misses and payment failures.",
                fault_type=FaultType.REDIS_FAILURE,
                target_service="payment-service",
                risk_level=RiskLevel.HIGH,
                parameters={"fail_percentage": 100},
                expected_telemetry="redis_errors_total counter spikes, payments_failed_total increments",
                expected_impact="Payment transactions fail; order-service returns payment processing errors",
            ),
            FaultScenario(
                id="INC-003",
                name="Payment Service Upstream Latency",
                description="Simulates severe network delay (+3000ms) on Payment Service HTTP endpoints.",
                fault_type=FaultType.SERVICE_LATENCY,
                target_service="payment-service",
                risk_level=RiskLevel.MEDIUM,
                parameters={"latency_ms": 3000},
                expected_telemetry="Payment service span latency increases, order-service upstream timeout",
                expected_impact="Order creation encounters payment timeout errors",
            ),
            FaultScenario(
                id="INC-004",
                name="Payment Gateway HTTP 500 Error Surge",
                description="Forces Payment Service to deterministically return HTTP 500 internal server errors.",
                fault_type=FaultType.SERVICE_ERROR_RATE,
                target_service="payment-service",
                risk_level=RiskLevel.HIGH,
                parameters={"error_code": 500, "error_rate": 1.0},
                expected_telemetry="http_requests_total with status_code=500, payments_failed_total increments",
                expected_impact="100% of payment operations aborted",
            ),
            FaultScenario(
                id="INC-005",
                name="Order Service Deployment Regression",
                description="Simulates regression in order-service v1.1 causing 50% synthetic exception rate after release.",
                fault_type=FaultType.DEPLOYMENT_REGRESSION,
                target_service="order-service",
                risk_level=RiskLevel.HIGH,
                parameters={"target_version": "1.1.0", "failure_rate": 0.5},
                expected_telemetry="Correlated deployment event followed immediately by 50% orders_failed_total increase",
                expected_impact="Half of all incoming orders fail immediately following release event",
            ),
        ]
        for s in canonical:
            self._scenarios[s.id] = s

    def list_all(self) -> list[FaultScenario]:
        return list(self._scenarios.values())

    def get(self, scenario_id: str) -> FaultScenario | None:
        return self._scenarios.get(scenario_id)

    def activate(self, scenario_id: str) -> FaultScenario:
        if scenario_id not in self._scenarios:
            raise KeyError(f"Scenario '{scenario_id}' not found")
        scenario = self._scenarios[scenario_id]
        scenario.enabled = True
        return scenario

    def deactivate(self, scenario_id: str) -> FaultScenario:
        if scenario_id not in self._scenarios:
            raise KeyError(f"Scenario '{scenario_id}' not found")
        scenario = self._scenarios[scenario_id]
        scenario.enabled = False
        return scenario

    def is_fault_active(self, target_service: str, fault_type: FaultType) -> FaultScenario | None:
        for s in self._scenarios.values():
            if s.enabled and s.target_service == target_service and s.fault_type == fault_type:
                return s
        return None

    def reset_all(self) -> None:
        """Safe recovery resetting all faults to inactive state."""
        for s in self._scenarios.values():
            s.enabled = False


# Global singleton instance for simulation runtime
simulation_registry = ScenarioRegistry()
