# Evidence Engine Architecture

The Evidence Engine collects, normalizes, deduplicates, and ranks multi-source telemetry and structural data within a bounded time window (T - 15m to T + 10m).

## Providers

1. **TelemetryEvidenceProvider**:
   - Collects metric deviations (latency, error surges), structured log warnings/errors (Loki), and slow/failed trace spans (OpenTelemetry).
   - Generates provenance strings (e.g. `prometheus:query(...)`, `loki:query(...)`, `otlp:trace_id=...`).
2. **DeploymentEvidenceProvider**:
   - Inspects release registries for deployments, version bumps, and git commit SHAs.
3. **SystemEvidenceProvider**:
   - Analyzes service dependency topology, upstream callers, and downstream datastores from the registry.
4. **CodeEvidenceProvider**:
   - Collects repository diffs, commit messages, and changed AST symbols.
5. **KnowledgeEvidenceProvider**:
   - Performs hybrid keyword/semantic search over runbooks and architecture documentation.

## Evidence Schema

```json
{
  "id": "uuid",
  "organization_id": "uuid",
  "investigation_id": "uuid",
  "evidence_type": "METRIC | LOG | TRACE | DEPLOYMENT | DEPENDENCY | CODE | KNOWLEDGE",
  "source": "prometheus | loki | otel | git | system-registry",
  "service_name": "order-service",
  "signal": "database_query_duration_seconds",
  "observed_at": "2026-10-03T10:00:00Z",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "content": "Database query latency spiked by +1500ms",
  "structured_data": {},
  "confidence": 0.98,
  "relevance_score": 0.94,
  "provenance": "prometheus:query(...)"
}
```

## Immutability & Deduplication

Evidence is append-only. Repeated observations within the same investigation window are merged or deduplicated using composite signal-provenance keys, preserving audit integrity.
