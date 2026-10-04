# Phase 1: Enterprise Foundation Architecture

## Scope & Deliverables
Phase 1 establishes the production backbone on which all future phases execute without requiring architectural refactoring:

### 1. Multi-Tenant Organizational Hierarchy
```text
Organization (Tenant Root)
   ├── Users & Memberships (RBAC roles)
   ├── Teams
   └── Projects
         └── Environments (e.g. Production, Staging)
               └── Services
```
Every entity is bound to an `organization_id`. Tenant boundaries are resolved and enforced server-side.

### 2. Database & Migrations
- **Engine**: PostgreSQL 16+ with `pgvector` enabled.
- **ORM**: SQLAlchemy 2.0 (asyncio + asyncpg).
- **Primary Keys**: UUIDv4 across all entities to prevent enumeration attacks.
- **Migrations**: Alembic migration lifecycle (`0001_initial_schema.py`) supporting full forward/rollback and reproducible offline SQL execution.

### 3. Identity Provider & RBAC Boundary
- AEGIS delegates identity management to external IdPs (OIDC / OAuth2 / JWT).
- Security Principal abstraction: `AuthenticatedPrincipal` resolves roles (`OWNER`, `ADMIN`, `ENGINEER`, `VIEWER`).
- Server-side permission matrix prevents unauthorized mutations and queries.

### 4. Storage & Cache Abstractions
- `ObjectStorage` interface decouples binary/evidence storage from specific vendors.
- MinIO operates as the local S3-compatible service; pluggable for AWS S3 or Google Cloud Storage in production.
- Redis manages caching, rate limiting, and ephemeral runtime state.

### 5. Observability & Security Middleware
- Structured JSON logging with automatic secret redaction.
- Dynamic `X-Request-ID` propagation and OpenTelemetry trace span binding.
- Security response headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`).
- Append-only `audit_events` logging for security-sensitive state transitions.
