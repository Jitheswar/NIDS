import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.keycloak_service import decode_token, extract_session_id
from services.session_service import (
    create_session,
    get_refresh_token,
    revoke_session,
    update_session_tokens,
)


async def _aiter_empty():
    return
    yield


@pytest.mark.asyncio
async def test_create_session_uses_provided_keycloak_sid():
    redis = AsyncMock()
    redis.scan_iter = MagicMock(return_value=_aiter_empty())
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()

    session_id = await create_session(redis, "user-1", "kc-session-1", "refresh-token")

    assert session_id == "kc-session-1"
    redis.set.assert_called_once()
    key_arg = redis.set.call_args.args[0]
    assert key_arg == "session:user-1:kc-session-1"


@pytest.mark.asyncio
async def test_create_session_rejects_missing_sid():
    redis = AsyncMock()
    redis.scan_iter = MagicMock(return_value=_aiter_empty())
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()

    with pytest.raises(ValueError):
        await create_session(redis, "user-1", "", "refresh-token")


def test_extract_session_id_prefers_sid():
    payload = {"sid": "sid-123", "session_state": "state-456"}
    assert extract_session_id(payload) == "sid-123"


def test_extract_session_id_falls_back_to_session_state():
    payload = {"session_state": "state-456"}
    assert extract_session_id(payload) == "state-456"


def test_extract_session_id_returns_none_if_missing():
    assert extract_session_id({}) is None


@pytest.mark.asyncio
async def test_decode_token_recovers_after_jwks_rotation():
    jwks_first = {"keys": [{"kid": "old", "kty": "RSA"}]}
    jwks_second = {"keys": [{"kid": "rotated", "kty": "RSA"}]}

    with patch(
        "services.keycloak_service.get_jwks",
        new=AsyncMock(side_effect=[jwks_first, jwks_second]),
    ) as mocked_get_jwks:
        with patch(
            "services.keycloak_service.jwt.algorithms.RSAAlgorithm.from_jwk",
            side_effect=lambda jwk: f'public-key-{jwk["kid"]}',
        ):
            with patch(
                "services.keycloak_service.jwt.get_unverified_header",
                return_value={"kid": "rotated"},
            ):
                with patch(
                    "services.keycloak_service.jwt.decode",
                    return_value={"sub": "user-1", "aud": "account"},
                ):
                    payload = await decode_token("token")

    assert payload["sub"] == "user-1"
    assert mocked_get_jwks.await_count == 2


class _FakeRedis:
    def __init__(self):
        self.store = {}

    async def scan_iter(self, match=None):
        prefix = match.rstrip("*") if match else ""
        for key in list(self.store.keys()):
            if key.startswith(prefix):
                yield key

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value

    async def delete(self, *keys):
        deleted = 0
        for key in keys:
            if key in self.store:
                del self.store[key]
                deleted += 1
        return deleted

    async def ttl(self, key):
        return 3600 if key in self.store else -2


@pytest.mark.asyncio
async def test_session_refresh_logout_flow():
    redis = _FakeRedis()
    user_id = "user-1"
    session_id = "kc-session-1"

    created = await create_session(redis, user_id, session_id, "refresh-1")
    assert created == session_id

    refresh = await get_refresh_token(redis, user_id, session_id)
    assert refresh == "refresh-1"

    updated = await update_session_tokens(redis, user_id, session_id, "refresh-2")
    assert updated is True

    refreshed = await get_refresh_token(redis, user_id, session_id)
    assert refreshed == "refresh-2"

    revoked = await revoke_session(redis, user_id, session_id)
    assert revoked is True

    missing = await get_refresh_token(redis, user_id, session_id)
    assert missing is None
