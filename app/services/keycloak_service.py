import asyncio
import time

import httpx
import jwt
import structlog
from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError

from config import settings

logger = structlog.get_logger()

# JWKS cache
_jwks_cache: dict = {}
_jwks_last_fetched: float = 0
_JWKS_CACHE_TTL = 300  # 5 minutes


def _get_keycloak_openid() -> KeycloakOpenID:
    return KeycloakOpenID(
        server_url=settings.keycloak_url,
        client_id=settings.keycloak_client_id,
        realm_name=settings.keycloak_realm,
        client_secret_key=settings.keycloak_client_secret.get_secret_value(),
    )


def _get_keycloak_admin() -> KeycloakAdmin:
    return KeycloakAdmin(
        server_url=settings.keycloak_url,
        username=settings.keycloak_admin_user,
        password=settings.keycloak_admin_password.get_secret_value(),
        realm_name=settings.keycloak_realm,
    )


async def authenticate(username: str, password: str) -> dict:
    """Authenticate user via Keycloak and return token pair."""
    kc = _get_keycloak_openid()
    try:
        token = await asyncio.to_thread(kc.token, username, password)
        return {
            "access_token": token["access_token"],
            "refresh_token": token["refresh_token"],
            "expires_in": token.get("expires_in", 900),
        }
    except KeycloakAuthenticationError:
        raise


async def refresh_token(refresh: str) -> dict:
    """Exchange a refresh token for new tokens."""
    kc = _get_keycloak_openid()
    token = await asyncio.to_thread(kc.refresh_token, refresh)
    return {
        "access_token": token["access_token"],
        "refresh_token": token["refresh_token"],
        "expires_in": token.get("expires_in", 900),
    }


async def logout_token(refresh: str) -> None:
    """Revoke a refresh token in Keycloak."""
    kc = _get_keycloak_openid()
    await asyncio.to_thread(kc.logout, refresh)


async def get_jwks() -> dict:
    """Fetch and cache Keycloak JWKS public keys."""
    global _jwks_cache, _jwks_last_fetched

    now = time.time()
    if _jwks_cache and (now - _jwks_last_fetched) < _JWKS_CACHE_TTL:
        return _jwks_cache

    jwks_url = f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/certs"
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_url)
        response.raise_for_status()
        _jwks_cache = response.json()
        _jwks_last_fetched = now
        logger.info("JWKS keys refreshed")
        return _jwks_cache


async def decode_token(access_token: str) -> dict:
    """Decode and verify a JWT access token using Keycloak's public keys."""
    jwks_data = await get_jwks()
    public_keys = {}

    for key_data in jwks_data.get("keys", []):
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
        public_keys[key_data["kid"]] = public_key

    unverified_header = jwt.get_unverified_header(access_token)
    kid = unverified_header.get("kid")

    if kid not in public_keys:
        # Try refreshing JWKS in case of key rotation
        global _jwks_last_fetched
        _jwks_last_fetched = 0
        jwks_data = await get_jwks()
        for key_data in jwks_data.get("keys", []):
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            public_keys[key_data["kid"]] = public_key

        if kid not in public_keys:
            raise jwt.InvalidTokenError("Unable to find matching key")

    payload = jwt.decode(
        access_token,
        key=public_keys[kid],
        algorithms=["RS256"],
        options={"verify_exp": True, "verify_aud": False},
    )

    return payload


def extract_roles(token_payload: dict) -> list[str]:
    """Extract realm roles from a decoded JWT payload."""
    realm_access = token_payload.get("realm_access", {})
    return realm_access.get("roles", [])


def extract_session_id(token_payload: dict) -> str | None:
    """Extract Keycloak session ID from token claims."""
    session_id = token_payload.get("sid") or token_payload.get("session_state")
    if not session_id:
        return None
    return str(session_id)
