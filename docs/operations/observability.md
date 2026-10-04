# Observability Guide & Dashboards

## Metrics Strategy
All metrics emitted follow Prometheus and OpenTelemetry low-cardinality standards:
- **HTTP**:
  - `http_requests_total` (`service`, `method`, `route`, `status_code`)
  - `http_request_duration_seconds` (`service`, `method`, `route`)
  - `http_in_flight_requests` (`service`)
- **Dependencies**:
  - `database_query_duration_seconds` (`service`, `operation`)
  - `database_errors_total` (`service`, `error_type`)
  - `redis_operation_duration_seconds` (`service`, `command`)
  - `redis_errors_total` (`service`, `command`)
- **Business**:
  - `orders_created_total`, `orders_failed_total`
  - `payments_attempted_total`, `payments_failed_total`
  - `user_requests_total`

## Cardinality Protection
High-cardinality identifiers (such as `user_id`, `order_id`, `request_id`, `payment_id`) are **strictly prohibited** from Prometheus labels. These identifiers reside solely in structured logs, event metadata, and trace span attributes.

## Grafana Provisioning
Dashboards and data sources are automatically provisioned via files:
- Data sources: `infrastructure/observability/grafana/provisioning/datasources/datasources.yml`
- Dashboard definition: `infrastructure/observability/grafana/dashboards/production_overview.json`

Access Grafana locally:
- URL: `http://localhost:3001`
- Credentials: `admin` / `admin`
