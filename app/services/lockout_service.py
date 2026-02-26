import time

import redis.asyncio as aioredis
import structlog

from config import settings

logger = structlog.get_logger()

FAILURE_PREFIX = "lockout:failures:"
TEMP_LOCK_PREFIX = "lockout:temp:"
PERM_LOCK_PREFIX = "lockout:perm:"


async def check_lockout(redis: aioredis.Redis, username: str) -> dict:
    """Check if a user is locked out.
    Returns {"locked": bool, "permanent": bool, "remaining": int (seconds)}
    """
    # Check permanent lock first
    perm_key = f"{PERM_LOCK_PREFIX}{username}"
    if await redis.exists(perm_key):
        return {"locked": True, "permanent": True, "remaining": -1}

    # Check temporary lock
    temp_key = f"{TEMP_LOCK_PREFIX}{username}"
    ttl = await redis.ttl(temp_key)
    if ttl > 0:
        return {"locked": True, "permanent": False, "remaining": ttl}

    return {"locked": False, "permanent": False, "remaining": 0}


async def record_failure(redis: aioredis.Redis, username: str) -> dict:
    """Record a failed login attempt. Returns lockout status after recording."""
    now = time.time()
    failure_key = f"{FAILURE_PREFIX}{username}"
    window_start = now - settings.permanent_lock_window

    # Add failure timestamp to sorted set
    await redis.zadd(failure_key, {str(now): now})

    # Remove entries outside the 24h window
    await redis.zremrangebyscore(failure_key, "-inf", window_start)

    # Set expiry on the sorted set
    await redis.expire(failure_key, settings.permanent_lock_window)

    # Count failures in window
    failure_count = await redis.zcard(failure_key)

    # Check permanent lock threshold (20 in 24h)
    if failure_count >= settings.permanent_lock_threshold:
        perm_key = f"{PERM_LOCK_PREFIX}{username}"
        await redis.set(perm_key, "1")  # No expiry — manual unlock required
        logger.warning("Account permanently locked", username=username, failures=failure_count)
        return {"locked": True, "permanent": True, "remaining": -1}

    # Check temporary lock threshold (5 failures)
    if failure_count >= settings.lockout_threshold:
        temp_key = f"{TEMP_LOCK_PREFIX}{username}"
        await redis.set(temp_key, "1", ex=settings.lockout_duration)
        logger.warning(
            "Account temporarily locked",
            username=username,
            failures=failure_count,
            duration=settings.lockout_duration,
        )
        return {"locked": True, "permanent": False, "remaining": settings.lockout_duration}

    return {"locked": False, "permanent": False, "remaining": 0}


async def reset_on_success(redis: aioredis.Redis, username: str) -> None:
    """Clear failure count on successful login."""
    failure_key = f"{FAILURE_PREFIX}{username}"
    temp_key = f"{TEMP_LOCK_PREFIX}{username}"
    await redis.delete(failure_key, temp_key)


async def unlock_account(redis: aioredis.Redis, username: str) -> bool:
    """Manually unlock a permanently locked account. Requires super_admin."""
    perm_key = f"{PERM_LOCK_PREFIX}{username}"
    failure_key = f"{FAILURE_PREFIX}{username}"
    temp_key = f"{TEMP_LOCK_PREFIX}{username}"

    existed = await redis.exists(perm_key)
    await redis.delete(perm_key, failure_key, temp_key)

    if existed:
        logger.info("Account manually unlocked", username=username)
    return bool(existed)
