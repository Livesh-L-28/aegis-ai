# AEGIS Security Model & Multi-Tenant Isolation

## 1. Authentication Boundary
AEGIS intentionally does not maintain insecure custom password databases. Authentication is architected around an external Identity Provider (OIDC / OAuth2 / JWT). In development and automated testing environments, test headers or mocked principals are used without altering application business logic.

## 2. Server-Side Tenant Isolation
Multi-tenant isolation is enforced at the database query and service layer, not client routing:
- Every tenant resource maintains an explicit `organization_id` foreign key.
- The `require_tenant_context` dependency verifies that incoming operations possess an authorized Organization context.
- SQL queries filter explicitly on `WHERE organization_id = :org_id`.
- Requests attempting to read, update, or delete resources belonging to another organization fail with `404 Not Found` (to prevent resource existence enumeration) or `403 Forbidden`.

## 3. Role-Based Access Control (RBAC)
Supported baseline roles:
- `OWNER`: Full administrative, read/write/delete privileges across all tenant resources and audit trails.
- `ADMIN`: Project and environment management, user administration, and audit read.
- `ENGINEER`: Project, environment, and service read/write privileges.
- `VIEWER`: Read-only access to tenant resources.

## 4. Defense-in-Depth Middleware
- **Security Headers**: Injected automatically on every response (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP`).
- **Request Size Limits**: Ingress payloads capped at 10MB to mitigate denial-of-service attempts.
- **Sensitive Key Redaction**: Custom logging formatter scans and masks credentials, passwords, and tokens before writing to stdout.
- **Append-Only Audit Logging**: All tenant and project creation/deletion events persist unmodifiable audit logs.
