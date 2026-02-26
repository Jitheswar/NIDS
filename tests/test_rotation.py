import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.rotation_service import RotationHealthChecker


def _make_redis_mock():
    redis = AsyncMock()
    redis.set = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.scan_iter = MagicMock(return_value=_async_iter([]))
    redis.info = AsyncMock(return_value={"used_memory": 50 * 1024 * 1024})  # 50MB
    return redis


async def _async_iter(items):
    for item in items:
        yield item


@pytest.mark.asyncio
async def test_check_session_health_normal():
    """Normal session count should produce no warnings."""
    redis = _make_redis_mock()
    checker = RotationHealthChecker(redis, AsyncMock())

    findings = await checker.check_session_health()

    # No critical or warning findings for low session count and memory
    severities = {f["severity"] for f in findings}
    assert "critical" not in severities
    assert "warning" not in severities


@pytest.mark.asyncio
async def test_check_session_health_high_memory():
    """High Redis memory should produce a warning."""
    redis = _make_redis_mock()
    redis.info = AsyncMock(return_value={"used_memory": 250 * 1024 * 1024})  # 250MB
    checker = RotationHealthChecker(redis, AsyncMock())

    findings = await checker.check_session_health()

    checks = {f["check"] for f in findings}
    assert "redis_memory_high" in checks


@pytest.mark.asyncio
async def test_check_keycloak_jwks_unreachable():
    """Unreachable Keycloak should produce critical finding."""
    redis = _make_redis_mock()
    checker = RotationHealthChecker(redis, AsyncMock())

    # Keycloak is not running in tests, so this should fail
    findings = await checker.check_keycloak_jwks()

    severities = {f["severity"] for f in findings}
    assert "critical" in severities


@pytest.mark.asyncio
async def test_check_ca_health_unreachable():
    """Unreachable step-ca should produce critical finding."""
    redis = _make_redis_mock()
    checker = RotationHealthChecker(redis, AsyncMock())

    findings = await checker.check_ca_health()

    severities = {f["severity"] for f in findings}
    assert "critical" in severities


@pytest.mark.asyncio
async def test_store_and_retrieve_results():
    """Health check results should be stored and retrievable."""
    redis = _make_redis_mock()
    stored_data = {}

    async def mock_set(key, value, **kwargs):
        stored_data[key] = value

    async def mock_get(key):
        return stored_data.get(key)

    redis.set = mock_set
    redis.get = mock_get

    checker = RotationHealthChecker(redis, AsyncMock())

    test_findings = [
        {"check": "test", "severity": "info", "message": "Test finding"},
    ]
    await checker._store_results(test_findings)

    results = await checker.get_latest_results()
    assert results is not None
    assert results["summary"]["total"] == 1
    assert results["summary"]["info"] == 1
