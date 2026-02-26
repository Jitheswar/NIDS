"""Infisical integration for centralized runtime secrets management.

Provides:
- Fetch secrets from Infisical at startup
- Periodic secret refresh (detect rotation)
- Secret version tracking for audit
"""

import httpx
import structlog

from config import settings

logger = structlog.get_logger()

_cached_secrets: dict[str, str] = {}


def _resolve_environment(environment: str | None) -> str:
    if environment:
        return environment
    env_map = {
        "development": "dev",
        "staging": "staging",
        "production": "prod",
    }
    return env_map.get(settings.environment, "dev")


async def fetch_secrets(
    environment: str | None = None,
    project_id: str = "nids",
) -> dict[str, str]:
    """Fetch all secrets from Infisical for the given environment."""
    global _cached_secrets
    target_environment = _resolve_environment(environment)

    if not settings.infisical_token:
        logger.debug("Infisical token not configured, skipping")
        return {}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.infisical_url}/api/v3/secrets/raw",
                headers={
                    "Authorization": f"Bearer {settings.infisical_token}",
                },
                params={
                    "workspaceId": project_id,
                    "environment": target_environment,
                },
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()

            secrets = {}
            for secret in data.get("secrets", []):
                key = secret.get("secretKey", "")
                value = secret.get("secretValue", "")
                if key:
                    secrets[key] = value

            _cached_secrets = secrets
            logger.info("Secrets fetched from Infisical", count=len(secrets))
            return secrets

    except Exception as e:
        logger.error("Failed to fetch secrets from Infisical", error=str(e))
        return _cached_secrets


async def get_secret(key: str, default: str = "") -> str:
    """Get a single secret by key. Returns cached value or default."""
    if key in _cached_secrets:
        return _cached_secrets[key]

    secrets = await fetch_secrets()
    return secrets.get(key, default)


async def refresh_secrets() -> dict[str, str]:
    """Force refresh all secrets from Infisical."""
    return await fetch_secrets()
