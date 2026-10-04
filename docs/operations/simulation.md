# Simulated Production Operations Guide

## Running the Complete Stack

1. **Start all infrastructure & simulated services**:
   ```bash
   make up
   # Or: docker compose up -d
   ```

2. **Verify simulated services**:
   - Gateway: `http://localhost:8080/health`
   - User Service: `http://localhost:8001/health`
   - Payment Service: `http://localhost:8002/health`
   - Order Service: `http://localhost:8000/health`
   - Prometheus: `http://localhost:9090`
   - Grafana: `http://localhost:3001` (admin / admin)
   - Loki: `http://localhost:3100`

3. **Simulating Customer Traffic**:
   ```bash
   curl -X POST http://localhost:8080/api/orders \
     -H "Content-Type: application/json" \
     -d '{"user_id": "usr_101", "items": ["item-1"], "total_amount": 99.0}'
   ```

4. **Triggering Incident Benchmarks via AEGIS API**:
   ```bash
   # Inject PostgreSQL query latency into Order Service
   curl -X POST http://localhost:8000/api/v1/simulation/scenarios/INC-001/activate \
     -H "X-Organization-ID: <ORG_UUID>" \
     -H "x-user-roles: OWNER"

   # Deactivate fault and restore normal operations
   curl -X POST http://localhost:8000/api/v1/simulation/scenarios/INC-001/deactivate \
     -H "X-Organization-ID: <ORG_UUID>" \
     -H "x-user-roles: OWNER"
   ```
