import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


@pytest.mark.asyncio
async def test_health_ready_ok(app_client):
    with patch("routers.health._check_database", new=AsyncMock(return_value={"status": "up"})):
        with patch("routers.health._check_redis", new=AsyncMock(return_value={"status": "up"})):
            with patch("routers.health._check_keycloak", new=AsyncMock(return_value={"status": "up"})):
                response = await app_client.get("/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["components"]["database"]["status"] == "up"
    assert body["components"]["redis"]["status"] == "up"
    assert body["components"]["keycloak"]["status"] == "up"


@pytest.mark.asyncio
async def test_health_ready_not_ready(app_client):
    with patch("routers.health._check_database", new=AsyncMock(return_value={"status": "down", "error": "db"})):
        with patch("routers.health._check_redis", new=AsyncMock(return_value={"status": "up"})):
            with patch("routers.health._check_keycloak", new=AsyncMock(return_value={"status": "up"})):
                response = await app_client.get("/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["components"]["database"]["status"] == "down"


@pytest.mark.asyncio
async def test_health_alias_matches_readiness(app_client):
    with patch("routers.health._check_database", new=AsyncMock(return_value={"status": "up"})):
        with patch("routers.health._check_redis", new=AsyncMock(return_value={"status": "down", "error": "redis"})):
            with patch("routers.health._check_keycloak", new=AsyncMock(return_value={"status": "up"})):
                response = await app_client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["components"]["redis"]["status"] == "down"
