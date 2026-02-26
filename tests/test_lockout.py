import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.lockout_service import check_lockout, record_failure, reset_on_success, unlock_account


@pytest.mark.asyncio
async def test_check_lockout_not_locked():
    """User should not be locked out by default."""
    redis = AsyncMock()
    redis.exists = AsyncMock(return_value=0)
    redis.ttl = AsyncMock(return_value=-1)

    result = await check_lockout(redis, "testuser")
    assert result["locked"] is False


@pytest.mark.asyncio
async def test_check_lockout_permanent():
    """User with permanent lock key should be locked."""
    redis = AsyncMock()
    redis.exists = AsyncMock(return_value=1)

    result = await check_lockout(redis, "testuser")
    assert result["locked"] is True
    assert result["permanent"] is True


@pytest.mark.asyncio
async def test_check_lockout_temporary():
    """User with temp lock key should be locked with remaining TTL."""
    redis = AsyncMock()
    redis.exists = AsyncMock(return_value=0)
    redis.ttl = AsyncMock(return_value=600)

    result = await check_lockout(redis, "testuser")
    assert result["locked"] is True
    assert result["permanent"] is False
    assert result["remaining"] == 600


@pytest.mark.asyncio
async def test_record_failure_below_threshold():
    """Recording a failure below threshold should not lock."""
    redis = AsyncMock()
    redis.zadd = AsyncMock()
    redis.zremrangebyscore = AsyncMock()
    redis.expire = AsyncMock()
    redis.zcard = AsyncMock(return_value=2)

    result = await record_failure(redis, "testuser")
    assert result["locked"] is False


@pytest.mark.asyncio
async def test_record_failure_at_threshold():
    """Recording failure at threshold should trigger temp lock."""
    redis = AsyncMock()
    redis.zadd = AsyncMock()
    redis.zremrangebyscore = AsyncMock()
    redis.expire = AsyncMock()
    redis.zcard = AsyncMock(return_value=5)
    redis.set = AsyncMock()

    result = await record_failure(redis, "testuser")
    assert result["locked"] is True
    assert result["permanent"] is False


@pytest.mark.asyncio
async def test_record_failure_permanent_threshold():
    """Recording failure at permanent threshold should permanently lock."""
    redis = AsyncMock()
    redis.zadd = AsyncMock()
    redis.zremrangebyscore = AsyncMock()
    redis.expire = AsyncMock()
    redis.zcard = AsyncMock(return_value=20)
    redis.set = AsyncMock()

    result = await record_failure(redis, "testuser")
    assert result["locked"] is True
    assert result["permanent"] is True


@pytest.mark.asyncio
async def test_reset_on_success():
    """Successful login should clear failure counters."""
    redis = AsyncMock()
    redis.delete = AsyncMock()

    await reset_on_success(redis, "testuser")
    redis.delete.assert_called_once()


@pytest.mark.asyncio
async def test_unlock_account():
    """Unlocking a locked account should clear all lockout keys."""
    redis = AsyncMock()
    redis.exists = AsyncMock(return_value=1)
    redis.delete = AsyncMock()

    result = await unlock_account(redis, "testuser")
    assert result is True
