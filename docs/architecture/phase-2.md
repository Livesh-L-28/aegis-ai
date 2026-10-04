# Phase 2: Production Simulation + Observability Architecture

## Overview
Phase 2 transforms AEGIS into a platform capable of observing and evaluating a realistic production-like application. It implements a complete simulated production topology, telemetry collection pipelines, Prometheus metrics, Grafana dashboards, Loki log aggregation, and a controlled fault-injection framework for incident simulation.

## Simulated Production Topology
```text
                    ┌─────────────────────────┐
                    │       API Gateway       │ (Port 8080)
                    └────────────┬────────────┘
                                 │
                     ┌───────────┼───────────┐
                     │           │           │
                     ▼           ▼           ▼
               User Service  Order Service  Payment Service (Port 8002)
               (Port 8001)   (Port 8000)     │
                     │           │           └──► Redis (Idempotency Cache)
                     │           ▼
                     └───────► PostgreSQL (Orders & Ledger)
```

## Shared Service Runtime (`packages/service_runtime`)
To eliminate boilerplate across simulated services, `packages/service_runtime` provides:
- Standardized FastAPI lifecycle and metadata endpoints (`/health`, `/ready`, `/metadata`)
- Correlation middleware propagating `X-Request-ID` and trace contexts
- Prometheus middleware scraping latency histograms (`http_request_duration_seconds`), counters (`http_requests_total`), and in-flight request gauges (`http_in_flight_requests`)
- Business domain metrics (`orders_created_total`, `orders_failed_total`, `payments_attempted_total`, `payments_failed_total`, `user_requests_total`)
- Structured JSON logging formatted for Loki ingestion

## Telemetry Flow & Observability Stack
1. **Prometheus**: Automatically scrapes `/metrics` across `aegis-api`, `gateway`, `order-service`, `payment-service`, and `user-service`.
2. **Loki**: Aggregates structured JSON logs for correlation across services.
3. **Grafana**: Pre-provisioned dashboards (`AEGIS Simulated Production Overview`) visualizing service request rates, error rates (5xx), p95 database query latency, Redis error spikes, and business throughput.

## Controlled Fault-Injection Benchmarks
The simulation runtime includes 5 canonical benchmarks in `packages/simulation/scenarios.py`:
- **INC-001**: PostgreSQL query latency injection (+1500ms on order persistence)
- **INC-002**: Redis connection failure (causes 100% payment idempotency failures and 503 errors)
- **INC-003**: Payment upstream network delay (+3000ms causing order timeouts)
- **INC-004**: Payment HTTP 500 error surge
- **INC-005**: Order Service deployment regression (induces unhandled exceptions following a release event)

All scenarios are strictly reversible via the `/api/v1/simulation/scenarios/{id}/deactivate` endpoint.
