from typing import Callable

import jwt
import redis.asyncio as aioredis
import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from config import settings
from services import keycloak_service, session_service, token_revocation_service

logger = structlog.get_logger()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_redis(request: Request) -> aioredis.Redis:
    return request.app.state.redis


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    redis: aioredis.Redis = Depends(get_redis),
) -> dict:
    """Decode JWT, check revocation, validate session, update idle timeout.
    Returns user claims."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = await keycloak_service.decode_token(token)
    except jwt.ExpiredSignatureError:
        raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception

    user_id = payload.get("sub")
    session_id = keycloak_service.extract_session_id(payload)
    jti = payload.get("jti", "")
    iat = payload.get("iat", 0)

    if not user_id:
        raise credentials_exception
    if not session_id:
        raise credentials_exception

    # Check if this specific token has been revoked
    if jti and await token_revocation_service.is_token_revoked(redis, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if all user tokens issued before a certain time are revoked
    if await token_revocation_service.is_user_token_revoked_before(redis, user_id, iat):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate session in Redis
    session = await session_service.validate_session(redis, user_id, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    roles = keycloak_service.extract_roles(payload)

    return {
        "sub": user_id,
        "username": payload.get("preferred_username", ""),
        "email": payload.get("email"),
        "first_name": payload.get("given_name"),
        "last_name": payload.get("family_name"),
        "roles": roles,
        "session_id": session_id,
        "jti": jti,
        "iat": iat,
    }


def require_role(*required_roles: str) -> Callable:
    """Dependency factory that checks if the current user has any of the required roles."""

    async def role_checker(
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        user_roles = set(current_user.get("roles", []))
        if not user_roles.intersection(required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(required_roles)}",
            )
        return current_user

    return role_checker


async def verify_sensor_mtls(request: Request) -> dict:
    """Verify sensor identity via mTLS client certificate.
    Used for sensor data submission endpoints when mTLS is enabled.
    """
    if not settings.mtls_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="mTLS is not enabled",
        )

    # Extract client certificate from TLS connection
    # In production, this comes from the reverse proxy (e.g., nginx)
    # via X-SSL-Client-Cert or X-Forwarded-Client-Cert header
    client_cert_header = request.headers.get("X-SSL-Client-Cert", "")
    client_cn = request.headers.get("X-SSL-Client-CN", "")
    client_serial = request.headers.get("X-SSL-Client-Serial", "")
    client_verified = request.headers.get("X-SSL-Client-Verify", "NONE")

    if client_verified != "SUCCESS" or not client_cn:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid client certificate required",
        )

    # Check CRL for revoked certificates
    from services.crl_service import is_certificate_revoked
    if client_serial and is_certificate_revoked(client_serial):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate has been revoked",
        )

    return {
        "cn": client_cn,
        "serial": client_serial,
        "verified": True,
    }
