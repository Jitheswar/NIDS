import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.token_revocation_service import (
    is_token_revoked,
    is_user_token_revoked_before,
    revoke_all_user_tokens,
    revoke_token,
)


@pytest.mark.asyncio
async def test_revoke_token():
    redis = AsyncMock()
    redis.set = AsyncMock()

    await revoke_token(redis, "jti-123", 900)
    redis.set.assert_called_once()
    call_args = redis.set.call_args
    assert "revoked_jwt:jti-123" in str(call_args)


@pytest.mark.asyncio
async def test_is_token_revoked_true():
    redis = AsyncMock()
    redis.exists = AsyncMock(return_value=1)

    result = await is_token_revoked(redis, "jti-123")
    assert result is True


@pytest.mark.asyncio
async def test_is_token_revoked_false():
    redis = AsyncMock()
    redis.exists = AsyncMock(return_value=0)

    result = await is_token_revoked(redis, "jti-456")
    assert result is False


@pytest.mark.asyncio
async def test_revoke_all_user_tokens():
    redis = AsyncMock()
    redis.set = AsyncMock()

    await revoke_all_user_tokens(redis, "user-123", 1700000000)
    redis.set.assert_called_once()


@pytest.mark.asyncio
async def test_is_user_token_revoked_before_true():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value="1700000100")

    # Token issued at 1700000050, revoked_before is 1700000100 => revoked
    result = await is_user_token_revoked_before(redis, "user-123", 1700000050)
    assert result is True


@pytest.mark.asyncio
async def test_is_user_token_revoked_before_false():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value="1700000100")

    # Token issued at 1700000200, revoked_before is 1700000100 => not revoked
    result = await is_user_token_revoked_before(redis, "user-123", 1700000200)
    assert result is False


@pytest.mark.asyncio
async def test_is_user_token_revoked_before_no_entry():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)

    result = await is_user_token_revoked_before(redis, "user-123", 1700000050)
    assert result is False
