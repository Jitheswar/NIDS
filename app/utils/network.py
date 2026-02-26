from starlette.requests import Request


def get_client_ip(request: Request) -> str:
    """Extract client IP with X-Forwarded-For support."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
