from packages.config.settings import Settings
from packages.logging.logger import mask_sensitive_data
from packages.security.rbac import AuthenticatedPrincipal, Permission, Role


def test_settings_defaults() -> None:
    settings = Settings()
    assert settings.APP_NAME in ["LogicFalcon (powered by AEGIS AI)", "AEGIS AI"]
    assert settings.PRODUCT_NAME == "LogicFalcon"
    assert settings.PLATFORM_NAME == "AEGIS AI"
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.ENVIRONMENT in ["development", "test", "staging", "production"]


def test_rbac_permissions() -> None:
    owner = AuthenticatedPrincipal(
        user_id="u1",
        email="owner@aegis.local",
        roles=[Role.OWNER],
    )
    assert owner.has_permission(Permission.ORG_WRITE) is True
    assert owner.has_permission(Permission.PROJECT_DELETE) is True
    assert owner.has_permission(Permission.AUDIT_READ) is True

    viewer = AuthenticatedPrincipal(
        user_id="u2",
        email="viewer@aegis.local",
        roles=[Role.VIEWER],
    )
    assert viewer.has_permission(Permission.ORG_READ) is True
    assert viewer.has_permission(Permission.PROJECT_WRITE) is False
    assert viewer.has_permission(Permission.PROJECT_DELETE) is False
    assert viewer.has_permission(Permission.AUDIT_READ) is False


def test_tenant_principal_boundary() -> None:
    principal = AuthenticatedPrincipal(
        user_id="u1",
        email="user@aegis.local",
        current_organization_id="11111111-1111-1111-1111-111111111111",
    )
    assert principal.can_access_tenant("11111111-1111-1111-1111-111111111111") is True
    assert principal.can_access_tenant("22222222-2222-2222-2222-222222222222") is False


def test_sensitive_data_logging_mask() -> None:
    payload = {
        "user": "test_user",
        "password": "SuperSecretPassword123!",
        "token": "bearer_jwt_token_here",
        "nested": {
            "api_key": "sk-1234567890",
            "normal_field": "visible_value",
        },
    }
    cleaned = mask_sensitive_data(payload)
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["token"] == "[REDACTED]"
    assert cleaned["nested"]["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["normal_field"] == "visible_value"
