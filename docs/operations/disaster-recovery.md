# Disaster Recovery & Resiliency Procedures

## 1. Authoritative State Recovery

PostgreSQL is the single source of authoritative state. Redis is strictly used as an ephemeral cache and circuit breaker flag store.

In the event of a Redis outage:
1. Operations fallback to fail-safe database queries.
2. In-memory circuit breakers default to safe state (`OPEN` for high risk).
3. Authoritative proposal hashes are validated against the PostgreSQL `remediations` table.

## 2. Model Provider Outage Failover

1. Primary provider fails or times out (> 10s).
2. The `ModelRouter` trips the provider circuit breaker.
3. Traffic fails over seamlessly to the secondary fallback model.
4. If all providers are unavailable, the system safely halts and escalates to human on-call engineers.
