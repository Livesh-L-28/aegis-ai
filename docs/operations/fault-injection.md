# Fault Injection Framework & Safety Model

## Safety Boundary
The Fault Injection Framework (`packages/simulation`) enables deterministic, controlled incident simulation. To ensure absolute safety:
1. **Target Restriction**: Fault injection is bounded strictly to services registered in the simulated production topology (`gateway`, `user-service`, `order-service`, `payment-service`).
2. **No Arbitrary Shell Execution**: Shell command execution, arbitrary IP manipulation, and arbitrary network teardown are strictly disallowed.
3. **Environment Boundary**: Only active in `production-sim` / `development` / `test` environments.
4. **Authorization & Tenant Scoping**: Triggering or resetting scenarios requires `ADMIN` or `OWNER` RBAC permissions and an active tenant context.
5. **Full Audit Trail**: Every scenario activation, deactivation, and simulated deployment generates an immutable entry in the `audit_events` database table.

## Canonical Benchmark Scenarios

| Scenario ID | Name | Target | Fault Type | Reversible |
| :--- | :--- | :--- | :--- | :--- |
| **INC-001** | PostgreSQL Latency Spike | `order-service` | `database_latency` | Yes |
| **INC-002** | Redis Dependency Failure | `payment-service` | `redis_failure` | Yes |
| **INC-003** | Upstream Service Latency | `payment-service` | `service_latency` | Yes |
| **INC-004** | HTTP 500 Error Surge | `payment-service` | `service_error_rate` | Yes |
| **INC-005** | Deployment Regression | `order-service` | `deployment_regression` | Yes |

## API Control Operations
- **List Scenarios**: `GET /api/v1/simulation/scenarios`
- **Inspect Scenario**: `GET /api/v1/simulation/scenarios/{id}`
- **Activate Scenario**: `POST /api/v1/simulation/scenarios/{id}/activate`
- **Deactivate Scenario**: `POST /api/v1/simulation/scenarios/{id}/deactivate`
- **Simulate Deployment**: `POST /api/v1/simulation/deployments`
