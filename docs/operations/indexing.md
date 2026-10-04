# Indexing Operations Guide

## Triggering Repository Indexing
Trigger an incremental indexing run via the AEGIS API:
```bash
curl -X POST http://localhost:8000/api/v1/intelligence/code/index \
  -H "X-Organization-ID: <ORG_UUID>" \
  -H "x-user-roles: OWNER"
```

## Searching Extracted Code Symbols
Search symbols across classes, functions, and methods:
```bash
curl -X POST http://localhost:8000/api/v1/intelligence/code/search \
  -H "X-Organization-ID: <ORG_UUID>" \
  -H "x-user-roles: VIEWER" \
  -H "Content-Type: application/json" \
  -d '{"query": "OrderService", "limit": 5}'
```
