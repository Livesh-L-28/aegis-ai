# Operational Investigation Workflow

## Investigation Lifecycle

Investigations proceed through strict lifecycle transitions:

```text
CREATED
   ↓
COLLECTING_EVIDENCE
   ↓
ANALYZING
   ↓
REASONING
   ↓
COMPLETED (or FAILED)
```

## API Operations

### 1. Create an Incident
```http
POST /api/v1/incidents
Headers:
  x-organization-id: <uuid>
  x-user-roles: OWNER

Body:
{
  "title": "PostgreSQL Query Latency Spike",
  "description": "Order placement requests experiencing elevated latency",
  "severity": "HIGH",
  "service_name": "order-service",
  "source": "SIMULATION"
}
```

### 2. Create an Investigation
```http
POST /api/v1/incidents/{incident_id}/investigations
Headers:
  x-organization-id: <uuid>
  x-user-roles: OWNER

Body:
{
  "created_by": "sre-engineer"
}
```

### 3. Run Investigation
```http
POST /api/v1/investigations/{investigation_id}/run
Headers:
  x-organization-id: <uuid>
  x-user-roles: OWNER
```

### 4. Inspect Results
```http
GET /api/v1/investigations/{investigation_id}/evidence
GET /api/v1/investigations/{investigation_id}/timeline
GET /api/v1/investigations/{investigation_id}/hypotheses
GET /api/v1/investigations/{investigation_id}/result
```

## Audit Trails
All key lifecycle operations emit append-only audit events:
- `incident.created`
- `investigation.created`
- `investigation.started`
- `evidence.collection.started`
- `evidence.collection.completed`
- `hypothesis.generated`
- `reasoning.started`
- `reasoning.completed` / `reasoning.failed`
