# Knowledge Ingestion & Hybrid Search Operations Guide

## Ingesting an Operational Runbook
```bash
curl -X POST http://localhost:8000/api/v1/intelligence/knowledge/documents \
  -H "X-Organization-ID: <ORG_UUID>" \
  -H "x-user-roles: OWNER" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "PostgreSQL Failover Runbook",
    "source_type": "RUNBOOK",
    "source_uri": "docs/runbooks/postgres.md",
    "content": "# PostgreSQL Latency\nTroubleshoot connection pool exhaustion and slow queries."
  }'
```

## Hybrid Retrieval
```bash
curl -X POST http://localhost:8000/api/v1/intelligence/knowledge/search \
  -H "X-Organization-ID: <ORG_UUID>" \
  -H "x-user-roles: VIEWER" \
  -H "Content-Type: application/json" \
  -d '{"query": "connection pool exhausted", "limit": 3}'
```

## Retrieving Unified System Context
```bash
curl http://localhost:8000/api/v1/intelligence/services/order-service/context \
  -H "X-Organization-ID: <ORG_UUID>" \
  -H "x-user-roles: VIEWER"
```
