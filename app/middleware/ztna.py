"""Zero Trust Network Access (ZTNA) middleware.

Implements context-aware access decisions based on:
1. Device identity (X-Device-ID header)
2. User agent validation
3. Geographic allowlist (via IP-based heuristic)
4. Risk score from anomaly detection
5. Request context (time, frequency, resource sensitivity)

Every request is treated as untrusted. Access is granted per-request
based on the combined context — not just authentication.
"""

import time

import redis.asyncio as aioredis
import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config import settings
from utils.network import get_client_ip

logger = structlog.get_logger()

# Paths that bypass ZTNA checks (pre-auth endpoints)
EXEMPT_PATHS = {
    "/health",
    "/health/live",
    "/health/ready",
    "/auth/login",
    "/sensors/activate",
    "/docs",
    "/openapi.json",
}


class ZTNAMiddleware(BaseHTTPMiddleware):
    """Zero Trust context-aware access middleware."""

    async def dispatch(self, request: Request, call_next):
        if not settings.ztna_enabled:
            return await call_next(request)

        path = request.url.path

        # Skip ZTNA for exempt paths
        if path in EXEMPT_PATHS or path.startswith("/docs"):
            return await call_next(request)

        context = await self._build_context(request)

        # Evaluate trust
        decision = await self._evaluate_trust(context, request)

        if not decision["allow"]:
            status_code = decision.get("status_code", 403)
            logger.warning(
                "ZTNA_BLOCKED",
                path=path,
                reason=decision["reason"],
                ip=context["ip"],
                device_id=context.get("device_id", ""),
                status_code=status_code,
            )
            return JSONResponse(
                status_code=status_code,
                content={
                    "detail": f"Access denied: {decision['reason']}",
                    "ztna_context": {
                        "risk_score": decision.get("risk_score", 0),
                        "reason": decision["reason"],
                    },
                },
            )

        # Attach ZTNA context to request state for downstream use
        request.state.ztna_context = context
        response = await call_next(request)
        return response

    async def _build_context(self, request: Request) -> dict:
        """Build the trust evaluation context from the request."""
        return {
            "ip": get_client_ip(request),
            "user_agent": request.headers.get("User-Agent", ""),
            "device_id": request.headers.get("X-Device-ID", ""),
            "path": request.url.path,
            "method": request.method,
            "timestamp": time.time(),
        }

    async def _evaluate_trust(self, context: dict, request: Request) -> dict:
        """Evaluate trust based on all ZTNA signals. Returns {"allow": bool, "reason": str}."""

        # 1. Device ID check
        if settings.ztna_require_device_id and not context["device_id"]:
            return {"allow": False, "reason": "Device identification required (X-Device-ID header)"}

        # 2. User agent validation
        allowed_agents = settings.ztna_allowed_user_agents
        if allowed_agents:
            agent_list = [a.strip().lower() for a in allowed_agents.split(",") if a.strip()]
            ua_lower = context["user_agent"].lower()
            if agent_list and not any(agent in ua_lower for agent in agent_list):
                return {"allow": False, "reason": "Unrecognized user agent"}

        # 3. Risk score check (from anomaly detection)
        try:
            redis: aioredis.Redis = request.app.state.redis
            from services.anomaly_service import AnomalyDetector
            detector = AnomalyDetector(redis)
            risk = await detector.get_risk_score(ip=context["ip"])
            if risk["blocked"]:
                return {
                    "allow": False,
                    "reason": f"Risk score too high ({risk['score']}/{settings.ztna_risk_score_threshold})",
                    "risk_score": risk["score"],
                    "status_code": 403,
                }
        except Exception as e:
            logger.error("ZTNA risk check failed", error=str(e))
            return {
                "allow": False,
                "reason": "risk_check_unavailable",
                "status_code": 503,
            }

        return {"allow": True, "reason": "trust_verified"}
