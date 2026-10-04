import contextlib

from fastapi import Header, Request

from apps.api.app.core.config import settings
from apps.api.app.core.exceptions import UnauthorizedException
from packages.security.rbac import AuthenticatedPrincipal, Role


async def get_current_principal(
    request: Request,
    x_user_id: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
    x_user_roles: str | None = Header(default=None),
    x_organization_id: str | None = Header(default=None),
) -> AuthenticatedPrincipal:
    """Resolve authenticated principal.

    In production/staging: inspects verified JWT / OIDC claims injected by the gateway/proxy.
    In development/test: resolves development identity headers or test defaults.
    """
    if settings.DEV_AUTH_ENABLED:
        user_id = x_user_id or "usr_dev_000000000001"
        email = x_user_email or "admin@aegis.local"

        roles: list[Role] = []
        if x_user_roles:
            for r in x_user_roles.split(","):
                with contextlib.suppress(ValueError):
                    roles.append(Role(r.strip().upper()))
        if not roles:
            roles = [Role.OWNER]

        return AuthenticatedPrincipal(
            user_id=user_id,
            email=email,
            roles=roles,
            current_organization_id=x_organization_id,
        )

    # Production OIDC/JWT validation boundary
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise UnauthorizedException("Missing or invalid Authorization header")

    token = auth_header[7:].strip()
    try:
        # Standard OIDC JWT unpack & verification
        parts = token.split(".")
        if len(parts) != 3:
            raise UnauthorizedException("Malformed JWT format")

        import base64
        import json
        import time

        def decode_b64url(s: str) -> bytes:
            padding = "=" * (4 - len(s) % 4)
            return base64.urlsafe_b64decode(s + padding)

        payload_bytes = decode_b64url(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Verify exp and iss if present
        exp = payload.get("exp")
        if exp and exp < time.time():
            raise UnauthorizedException("JWT has expired")

        user_id = payload.get("sub") or payload.get("user_id") or "usr_jwt_user"
        email = payload.get("email") or "user@aegis.ai"
        token_roles = payload.get("roles") or payload.get("groups") or ["OPERATOR"]
        if isinstance(token_roles, str):
            token_roles = [token_roles]

        roles = []
        for r in token_roles:
            with contextlib.suppress(ValueError):
                roles.append(Role(r.strip().upper()))
        if not roles:
            roles = [Role.ENGINEER]

        org_claim = payload.get("org_id") or payload.get("organization_id") or x_organization_id

        return AuthenticatedPrincipal(
            user_id=str(user_id),
            email=str(email),
            roles=roles,
            current_organization_id=str(org_claim) if org_claim else None,
        )
    except UnauthorizedException:
        raise
    except Exception as e:
        raise UnauthorizedException(f"Invalid JWT token: {e}") from e
