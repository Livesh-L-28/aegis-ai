# AEGIS API Versioning & Contracts

All public API endpoints are versioned under `/api/v1/`.

## Endpoints

### System Endpoints
- `GET /api/v1/health`
  Liveness probe returning process health and version information.
  ```json
  {
    "status": "ok",
    "service": "AEGIS AI",
    "version": "0.1.0"
  }
  ```

- `GET /api/v1/ready`
  Readiness probe actively querying PostgreSQL, Redis, and Object Storage connections.
  ```json
  {
    "status": "ready",
    "dependencies": {
      "postgres": {"status": "healthy", "latency_ms": 1.4},
      "redis": {"status": "healthy", "latency_ms": 0.8},
      "object_storage": {"status": "healthy", "latency_ms": null}
    }
  }
  ```

- `GET /api/v1/version`
  Metadata endpoint returning deployment version, environment, and API specification.

### Tenant & Domain Endpoints
- `POST /api/v1/organizations` — Register tenant organization
- `GET /api/v1/organizations` — List organizations accessible by current principal
- `GET /api/v1/organizations/{id}` — Fetch specific organization

- `POST /api/v1/projects` — Create project within tenant context (Requires `X-Organization-ID` header)
- `GET /api/v1/projects` — List projects for current organization
- `GET /api/v1/projects/{id}` — Fetch specific project within current organization
- `PATCH /api/v1/projects/{id}` — Update project within current organization
- `DELETE /api/v1/projects/{id}` — Delete project within current organization

- `GET /api/v1/audit` — Query tenant audit trail events

## Standard Error Response Format
All errors adhere to a safe, non-leaking JSON envelope:
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Project '...' not found",
    "request_id": "8b51d6c8-1111-4444-9999-000000000000",
    "details": {}
  }
}
```
Stack traces and raw database error strings are suppressed in responses.
