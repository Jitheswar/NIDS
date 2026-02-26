import asyncio

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from config import settings
from database import async_session

router = APIRouter(tags=["Health"])


async def _check_database() -> dict:
    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "up"}
    except Exception as exc:
        return {"status": "down", "error": str(exc)}


async def _check_redis(request: Request) -> dict:
    try:
        await request.app.state.redis.ping()
        return {"status": "up"}
    except Exception as exc:
        return {"status": "down", "error": str(exc)}


async def _check_keycloak() -> dict:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/.well-known/openid-configuration",
                timeout=5.0,
            )
            response.raise_for_status()
        return {"status": "up"}
    except Exception as exc:
        return {"status": "down", "error": str(exc)}


async def _build_readiness_payload(request: Request) -> tuple[dict, bool]:
    db_status, redis_status, keycloak_status = await asyncio.gather(
        _check_database(),
        _check_redis(request),
        _check_keycloak(),
    )

    components = {
        "database": db_status,
        "redis": redis_status,
        "keycloak": keycloak_status,
    }
    ready = all(component["status"] == "up" for component in components.values())

    payload = {
        "service": "nids-api",
        "status": "ready" if ready else "not_ready",
        "components": components,
    }
    return payload, ready


@router.get("/health/live")
async def health_live():
    return {"status": "alive", "service": "nids-api"}


@router.get("/health/ready")
async def health_ready(request: Request):
    payload, ready = await _build_readiness_payload(request)
    status_code = 200 if ready else 503
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/health")
async def health(request: Request):
    payload, ready = await _build_readiness_payload(request)
    status_code = 200 if ready else 503
    return JSONResponse(status_code=status_code, content=payload)
