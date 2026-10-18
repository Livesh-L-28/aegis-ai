"""Tests for FastAPI Code Review endpoints, authorization, and lifecycle."""

import hashlib
import hmac

import pytest
from httpx import AsyncClient

SAMPLE_REVIEW_DIFF = """diff --git a/pkg/service.py b/pkg/service.py
new file mode 100644
--- /dev/null
+++ b/pkg/service.py
@@ -0,0 +1,5 @@
+def compute():
+    eval("untrusted")
+    return 100
+"""


@pytest.mark.asyncio
async def test_review_api_lifecycle(client: AsyncClient) -> None:
    # 1. Create Organization first
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Review Org", "slug": "review-org"},
        headers={"x-user-roles": "OWNER"},
    )
    assert org_res.status_code == 201
    org_id = org_res.json()["id"]

    # 2. Trigger Code Review
    headers = {
        "x-organization-id": org_id,
        "x-user-roles": "ENGINEER",
    }
    payload = {
        "repository_name": "AEGIS AI",
        "diff_text": SAMPLE_REVIEW_DIFF,
        "enable_ai": False,
    }
    create_res = await client.post("/api/v1/reviews", json=payload, headers=headers)
    assert create_res.status_code == 201
    review_data = create_res.json()
    review_id = review_data["id"]
    assert review_data["repository_name"] == "AEGIS AI"
    assert review_data["status"] in ("PENDING", "RUNNING", "COMPLETED")

    # 3. Retrieve Review Status
    get_res = await client.get(f"/api/v1/reviews/{review_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == review_id

    # 4. List Review History
    list_res = await client.get("/api/v1/reviews", headers=headers)
    assert list_res.status_code == 200
    assert any(r["id"] == review_id for r in list_res.json())

    # 5. Cancel Review Endpoint
    cancel_res = await client.post(
        f"/api/v1/reviews/{review_id}/cancel",
        json={"reason": "Test cancel"},
        headers=headers,
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"
    assert cancel_res.json()["cancellation_reason"] == "Test cancel"


@pytest.mark.asyncio
async def test_review_api_rbac_enforcement(client: AsyncClient) -> None:
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "RBAC Org", "slug": "rbac-org"},
        headers={"x-user-roles": "OWNER"},
    )
    org_id = org_res.json()["id"]

    # VIEWER cannot create a review (requires PROJECT_WRITE)
    viewer_headers = {
        "x-organization-id": org_id,
        "x-user-roles": "VIEWER",
    }
    create_res = await client.post(
        "/api/v1/reviews",
        json={"repository_name": "Test", "diff_text": ""},
        headers=viewer_headers,
    )
    assert create_res.status_code == 403


@pytest.mark.asyncio
async def test_github_webhook_endpoint(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "test-configured-webhook-secret"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)
    payload = b'{"action": "opened", "pull_request": {"number": 10}}'
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    # Valid webhook
    valid_res = await client.post(
        "/api/v1/reviews/github/webhook",
        content=payload,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "test-delivery-id",
        },
    )
    assert valid_res.status_code == 200
    assert valid_res.json()["status"] == "accepted"

    # Unauthorized webhook (bad sig)
    bad_res = await client.post(
        "/api/v1/reviews/github/webhook",
        content=payload,
        headers={
            "X-Hub-Signature-256": "sha256=invalid",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert bad_res.status_code == 401
