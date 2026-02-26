import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import redis.asyncio as aioredis
import structlog
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_limiter import FastAPILimiter

from config import settings
from database import engine, async_session
from middleware.audit import AuditMiddleware
from middleware.ztna import ZTNAMiddleware
from routers import auth, sensors, health, audit, security

logger = structlog.get_logger()


def _run_migrations() -> None:
    app_dir = Path(__file__).resolve().parent
    alembic_cfg = Config(str(app_dir / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(app_dir / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(alembic_cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting NIDS API", environment=settings.environment)

    # Initialize Redis
    redis_client = aioredis.from_url(
        settings.redis_url, encoding="utf-8", decode_responses=True
    )
    app.state.redis = redis_client
    await FastAPILimiter.init(redis_client)

    # Run schema migrations
    await asyncio.to_thread(_run_migrations)
    logger.info("Database migrations applied")

    background_tasks = []

    # Phase 2: CRL refresh loop
    if settings.mtls_enabled:
        from services.crl_service import start_crl_refresh_loop
        task = asyncio.create_task(start_crl_refresh_loop())
        background_tasks.append(task)
        logger.info("CRL refresh loop started", interval=settings.crl_refresh_interval)

    # Phase 3: Rotation health check loop
    from services.rotation_service import start_rotation_check_loop
    task = asyncio.create_task(
        start_rotation_check_loop(redis_client, async_session)
    )
    background_tasks.append(task)
    logger.info("Rotation health check loop started", interval=settings.rotation_check_interval)

    # Phase 3: Fetch secrets from Infisical (if configured)
    if settings.infisical_token:
        from services.infisical_service import fetch_secrets
        await fetch_secrets()
        logger.info("Secrets loaded from Infisical")

    logger.info("NIDS API started successfully")
    yield

    # Shutdown — cancel all background tasks
    for task in background_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    await redis_client.close()
    await engine.dispose()
    await FastAPILimiter.close()
    logger.info("NIDS API shut down")


app = FastAPI(
    title="NIDS API",
    description="AI-Based Network Intrusion Detection System",
    version="0.3.0",
    lifespan=lifespan,
)

# CORS — environment-aware allowlist
_cors_origins = {
    "development": ["http://localhost:3000", "http://localhost:8080"],
    "staging": ["https://staging-dashboard.example.com"],
    "production": ["https://dashboard.example.com"],
}
allowed_origins = settings.cors_origin_list or _cors_origins.get(settings.environment, [])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=[
        "Authorization", "Content-Type",
        "X-SSL-Client-Cert", "X-SSL-Client-CN", "X-SSL-Client-Serial", "X-SSL-Client-Verify",
        "X-Device-ID",
    ],
)

# ZTNA middleware (Phase 3) — must be before audit to block untrusted requests early
app.add_middleware(ZTNAMiddleware)

# Audit logging middleware
app.add_middleware(AuditMiddleware)

# Routers
app.include_router(health.router)
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(sensors.router, prefix="/sensors", tags=["Sensors"])
app.include_router(audit.router, prefix="/audit", tags=["Audit"])
app.include_router(security.router, prefix="/security", tags=["Security"])
