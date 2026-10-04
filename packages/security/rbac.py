from enum import StrEnum

from pydantic import BaseModel, Field


class Role(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    ENGINEER = "ENGINEER"
    VIEWER = "VIEWER"


class Permission(StrEnum):
    # Organization
    ORG_READ = "organization:read"
    ORG_WRITE = "organization:write"
    ORG_DELETE = "organization:delete"

    # Project
    PROJECT_READ = "project:read"
    PROJECT_WRITE = "project:write"
    PROJECT_DELETE = "project:delete"

    # Environment
    ENV_READ = "environment:read"
    ENV_WRITE = "environment:write"
    ENV_DELETE = "environment:delete"

    # Service
    SERVICE_READ = "service:read"
    SERVICE_WRITE = "service:write"
    SERVICE_DELETE = "service:delete"

    # Audit & Security
    AUDIT_READ = "audit:read"

    # Remediation
    REMEDIATION_READ = "remediation:read"
    REMEDIATION_PROPOSE = "remediation:propose"
    REMEDIATION_APPROVE = "remediation:approve"
    REMEDIATION_EXECUTE = "remediation:execute"

    # Autonomy & Production Hardening (Phase 7)
    AUTONOMY_READ = "autonomy:read"
    AUTONOMY_ADMIN = "autonomy:admin"


# Standard RBAC Role -> Permissions Mapping Matrix
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.OWNER: {
        Permission.ORG_READ,
        Permission.ORG_WRITE,
        Permission.ORG_DELETE,
        Permission.PROJECT_READ,
        Permission.PROJECT_WRITE,
        Permission.PROJECT_DELETE,
        Permission.ENV_READ,
        Permission.ENV_WRITE,
        Permission.ENV_DELETE,
        Permission.SERVICE_READ,
        Permission.SERVICE_WRITE,
        Permission.SERVICE_DELETE,
        Permission.AUDIT_READ,
        Permission.REMEDIATION_READ,
        Permission.REMEDIATION_PROPOSE,
        Permission.REMEDIATION_APPROVE,
        Permission.REMEDIATION_EXECUTE,
        Permission.AUTONOMY_READ,
        Permission.AUTONOMY_ADMIN,
    },
    Role.ADMIN: {
        Permission.ORG_READ,
        Permission.ORG_WRITE,
        Permission.PROJECT_READ,
        Permission.PROJECT_WRITE,
        Permission.PROJECT_DELETE,
        Permission.ENV_READ,
        Permission.ENV_WRITE,
        Permission.ENV_DELETE,
        Permission.SERVICE_READ,
        Permission.SERVICE_WRITE,
        Permission.SERVICE_DELETE,
        Permission.AUDIT_READ,
        Permission.REMEDIATION_READ,
        Permission.REMEDIATION_PROPOSE,
        Permission.REMEDIATION_APPROVE,
        Permission.REMEDIATION_EXECUTE,
        Permission.AUTONOMY_READ,
        Permission.AUTONOMY_ADMIN,
    },
    Role.ENGINEER: {
        Permission.ORG_READ,
        Permission.PROJECT_READ,
        Permission.PROJECT_WRITE,
        Permission.ENV_READ,
        Permission.ENV_WRITE,
        Permission.SERVICE_READ,
        Permission.SERVICE_WRITE,
        Permission.REMEDIATION_READ,
        Permission.REMEDIATION_PROPOSE,
        Permission.REMEDIATION_EXECUTE,
        Permission.AUTONOMY_READ,
    },
    Role.VIEWER: {
        Permission.ORG_READ,
        Permission.PROJECT_READ,
        Permission.ENV_READ,
        Permission.SERVICE_READ,
        Permission.REMEDIATION_READ,
        Permission.AUTONOMY_READ,
    },
}



class AuthenticatedPrincipal(BaseModel):
    user_id: str
    email: str
    roles: list[Role] = Field(default_factory=lambda: [Role.VIEWER])
    current_organization_id: str | None = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if any assigned role grants the specified permission."""
        return any(permission in ROLE_PERMISSIONS.get(role, set()) for role in self.roles)

    def can_access_tenant(self, organization_id: str) -> bool:
        """Enforce strict tenant boundary."""
        if not self.current_organization_id:
            return False
        return str(self.current_organization_id) == str(organization_id)
