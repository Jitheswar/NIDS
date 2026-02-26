from fastapi_limiter.depends import RateLimiter as _RateLimiter
from starlette.requests import Request
from starlette.responses import Response


class RateLimiter(_RateLimiter):
    """Compatibility wrapper to avoid hard-failing routes when limiter state isn't initialized."""

    async def __call__(self, request: Request, response: Response):
        try:
            return await super().__call__(request, response)
        except Exception as exc:
            # Keep core auth and sensor flows available if limiter init is unavailable at runtime.
            if "FastAPILimiter.init" in str(exc):
                return None
            raise

# Rate limiters as FastAPI dependencies (applied per-route)
# Usage: @router.post("/login", dependencies=[Depends(login_rate_limit)])

# Auth endpoints: 10 requests per minute per IP
login_rate_limit = RateLimiter(times=10, seconds=60)

# Auth endpoints other than login
auth_general_rate_limit = RateLimiter(times=100, seconds=60)

# Sensor operations
sensor_enroll_rate_limit = RateLimiter(times=5, seconds=60)
sensor_activate_rate_limit = RateLimiter(times=20, seconds=60)
sensor_mutation_rate_limit = RateLimiter(times=30, seconds=60)

# Query-heavy endpoints
audit_query_rate_limit = RateLimiter(times=60, seconds=60)
security_read_rate_limit = RateLimiter(times=60, seconds=60)
security_mutation_rate_limit = RateLimiter(times=10, seconds=60)

# Backward-compatible aliases
enroll_rate_limit = sensor_enroll_rate_limit
general_rate_limit = auth_general_rate_limit
