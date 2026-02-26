import pytest
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_health_live_check(app_client):
    """Liveness endpoint should always return 200."""
    response = await app_client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"


@pytest.mark.asyncio
async def test_login_missing_fields(app_client):
    """Login without required fields should return 422."""
    response = await app_client.post("/auth/login", json={})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_empty_username(app_client):
    """Login with empty username should return 422."""
    response = await app_client.post(
        "/auth/login", json={"username": "", "password": "test"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_me_no_token(app_client):
    """GET /auth/me without token should return 401."""
    response = await app_client.get("/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_invalid_token(app_client):
    """GET /auth/me with invalid token should return 401."""
    response = await app_client.get(
        "/auth/me", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_sensors_no_auth(app_client):
    """Sensor endpoints without auth should return 401."""
    response = await app_client.get("/sensors/")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_sensors_create_no_auth(app_client):
    """Creating sensor without auth should return 401."""
    response = await app_client.post(
        "/sensors/",
        json={"name": "test-sensor", "network_segment": "172.28.0.0/16"},
    )
    assert response.status_code == 401
