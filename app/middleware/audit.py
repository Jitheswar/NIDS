import time

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from utils.network import get_client_ip

logger = structlog.get_logger()


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs every HTTP request with method, path, status, duration, and client IP."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()

        response = await call_next(request)

        duration_ms = round((time.time() - start_time) * 1000, 2)

        logger.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            ip=get_client_ip(request),
        )

        return response
