"""Phase 6 Unit Tests: Controlled Git Provider, Patch validation, and PR creation."""

import pytest

from packages.remediation.providers.git import ControlledGitProvider


def test_git_patch_validation_clean_diff() -> None:
    provider = ControlledGitProvider()
    clean_diff = """--- a/apps/simulated_production/order_service/main.py
+++ b/apps/simulated_production/order_service/main.py
@@ -10,3 +10,4 @@
 def query_db():
+    timeout = 2.0
     return "ok"
"""
    result = provider.validate_patch(clean_diff)
    assert result.valid is True
    assert "apps/simulated_production/order_service/main.py" in result.files_changed


def test_git_patch_rejects_credential_leak() -> None:
    provider = ControlledGitProvider()
    dirty_diff = """--- a/config.py
+++ b/config.py
@@ -1,2 +1,3 @@
+secret_key = "sk-live-123456789"
"""
    result = provider.validate_patch(dirty_diff)
    assert result.valid is False
    assert any("secret" in err.lower() for err in result.security_violations)


def test_git_patch_rejects_protected_files() -> None:
    provider = ControlledGitProvider()
    bad_diff = """--- a/.env
+++ b/.env
@@ -1,1 +1,2 @@
+NEW_VAR=1
"""
    result = provider.validate_patch(bad_diff)
    assert result.valid is False
    assert any("restricted" in err.lower() for err in result.security_violations)


def test_git_branch_and_pull_request_workflow() -> None:
    provider = ControlledGitProvider()

    # Protected branch modification blocked
    with pytest.raises(PermissionError, match="Direct commits to protected branches"):
        provider.create_branch("aegis-core", "main", base_branch="main")

    # Isolated branch creation
    branch = provider.create_branch("aegis-core", "aegis/remediation/INC-001/patch-1")
    assert branch == "aegis/remediation/INC-001/patch-1"

    # Pull Request creation
    pr = provider.create_pull_request(
        repo_name="aegis-core",
        branch_name=branch,
        title="[AEGIS AI] Automated Fix for INC-001",
        body="Diff payload",
    )
    assert pr.pr_number >= 100
    assert pr.branch_name == branch
    assert "aegis-enterprise" in pr.url
