import redis.asyncio as aioredis
import structlog

from config import settings

logger = structlog.get_logger()

REVOKED_PREFIX = settings.jwt_revocation_prefix


async def revoke_token(redis: aioredis.Redis, jti: str, expires_in: int) -> None:
    """Add a JWT ID (jti) to the revocation blacklist.
    The entry auto-expires when the token would have expired anyway.
    """
    key = f"{REVOKED_PREFIX}{jti}"
    await redis.set(key, "1", ex=expires_in)
    logger.info("JWT revoked", jti=jti, expires_in=expires_in)


async def is_token_revoked(redis: aioredis.Redis, jti: str) -> bool:
    """Check if a JWT has been revoked."""
    key = f"{REVOKED_PREFIX}{jti}"
    return bool(await redis.exists(key))


async def revoke_all_user_tokens(
    redis: aioredis.Redis, user_id: str, current_time: int, max_token_lifetime: int = 900
) -> None:
    """Revoke all tokens for a user by storing a 'revoked_before' timestamp.
    Any token issued before this timestamp is considered revoked.
    """
    key = f"{REVOKED_PREFIX}user:{user_id}"
    await redis.set(key, str(current_time), ex=max_token_lifetime)
    logger.info("All tokens revoked for user", user_id=user_id)


async def is_user_token_revoked_before(
    redis: aioredis.Redis, user_id: str, issued_at: int
) -> bool:
    """Check if a user's tokens issued before a certain time are revoked."""
    key = f"{REVOKED_PREFIX}user:{user_id}"
    revoked_before = await redis.get(key)
    if revoked_before and issued_at <= int(revoked_before):
        return True
    return False
