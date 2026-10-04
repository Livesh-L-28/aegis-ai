import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_error_envelope_schema_contract(client: AsyncClient) -> None:
    # Trigger 404
    res = await client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000", headers={"x-organization-id": "11111111-1111-1111-1111-111111111111"})
    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert "code" in data["error"]
    assert "message" in data["error"]
    assert "request_id" in data["error"]
    assert "X-Request-ID" in res.headers


@pytest.mark.asyncio
async def test_validation_envelope_schema_contract(client: AsyncClient) -> None:
    # Trigger validation failure (missing slug)
    res = await client.post(
        "/api/v1/organizations",
        json={"name": "Incomplete"},
        headers={"x-user-roles": "OWNER"},
    )
    assert res.status_code == 422
