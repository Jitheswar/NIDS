import json
import time

import redis.asyncio as aioredis
import structlog

from config import settings

logger = structlog.get_logger()

SESSION_PREFIX = "session:"


async def create_session(
    redis: aioredis.Redis,
    user_id: str,
    session_id: str,
    refresh_token: str,
) -> str:
    """Create a new session in Redis. Enforces concurrent session limit."""
    if not session_id:
        raise ValueError("session_id is required")

    await _enforce_concurrent_limit(redis, user_id)

    key = f"{SESSION_PREFIX}{user_id}:{session_id}"
    now = time.time()

    session_data = {
        "refresh_token": refresh_token,
        "created_at": now,
        "last_active": now,
    }

    await redis.set(key, json.dumps(session_data), ex=settings.session_absolute_timeout)
    logger.info("Session created", user_id=user_id, session_id=session_id)
    return session_id


async def validate_session(
    redis: aioredis.Redis,
    user_id: str,
    session_id: str,
) -> dict | None:
    """Validate a session exists and hasn't exceeded idle timeout.
    Returns session data or None if invalid."""
    key = f"{SESSION_PREFIX}{user_id}:{session_id}"
    data = await redis.get(key)

    if not data:
        return None

    session = json.loads(data)
    now = time.time()

    # Check idle timeout
    last_active = session.get("last_active", 0)
    if (now - last_active) > settings.session_idle_timeout:
        await redis.delete(key)
        logger.info("Session expired (idle)", user_id=user_id, session_id=session_id)
        return None

    # Update last_active (touch)
    session["last_active"] = now
    ttl = await redis.ttl(key)
    if ttl > 0:
        await redis.set(key, json.dumps(session), ex=ttl)

    return session


async def get_refresh_token(
    redis: aioredis.Redis,
    user_id: str,
    session_id: str,
) -> str | None:
    """Get the refresh token from a valid session."""
    session = await validate_session(redis, user_id, session_id)
    if not session:
        return None
    return session.get("refresh_token")


async def update_session_tokens(
    redis: aioredis.Redis,
    user_id: str,
    session_id: str,
    new_refresh_token: str,
) -> bool:
    """Update the refresh token in an existing session."""
    key = f"{SESSION_PREFIX}{user_id}:{session_id}"
    data = await redis.get(key)

    if not data:
        return False

    session = json.loads(data)
    session["refresh_token"] = new_refresh_token
    session["last_active"] = time.time()

    ttl = await redis.ttl(key)
    if ttl > 0:
        await redis.set(key, json.dumps(session), ex=ttl)

    return True


async def revoke_session(
    redis: aioredis.Redis,
    user_id: str,
    session_id: str,
) -> bool:
    """Delete a session from Redis."""
    key = f"{SESSION_PREFIX}{user_id}:{session_id}"
    deleted = await redis.delete(key)
    if deleted:
        logger.info("Session revoked", user_id=user_id, session_id=session_id)
    return bool(deleted)


async def revoke_all_sessions(redis: aioredis.Redis, user_id: str) -> int:
    """Delete all sessions for a user."""
    pattern = f"{SESSION_PREFIX}{user_id}:*"
    keys = []
    async for key in redis.scan_iter(match=pattern):
        keys.append(key)

    if keys:
        deleted = await redis.delete(*keys)
        logger.info("All sessions revoked", user_id=user_id, count=deleted)
        return deleted
    return 0


async def _enforce_concurrent_limit(redis: aioredis.Redis, user_id: str) -> None:
    """If user has >= max concurrent sessions, delete the oldest."""
    pattern = f"{SESSION_PREFIX}{user_id}:*"
    sessions = []

    async for key in redis.scan_iter(match=pattern):
        data = await redis.get(key)
        if data:
            session = json.loads(data)
            sessions.append((key, session.get("created_at", 0)))

    if len(sessions) >= settings.session_max_concurrent:
        # Sort by creation time, delete oldest
        sessions.sort(key=lambda x: x[1])
        to_remove = len(sessions) - settings.session_max_concurrent + 1
        for key, _ in sessions[:to_remove]:
            await redis.delete(key)
            logger.info("Evicted oldest session", user_id=user_id, key=key)
