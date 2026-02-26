import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Add app directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from database import Base  # noqa: E402


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def mock_redis():
    """Mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.delete = AsyncMock(return_value=1)
    redis.exists = AsyncMock(return_value=0)
    redis.ttl = AsyncMock(return_value=-1)
    redis.zadd = AsyncMock()
    redis.zcard = AsyncMock(return_value=0)
    redis.zremrangebyscore = AsyncMock()
    redis.expire = AsyncMock()
    redis.scan_iter = MagicMock(return_value=aiter_empty())
    return redis


async def aiter_empty():
    """Empty async iterator."""
    return
    yield  # noqa: make it an async generator


@pytest_asyncio.fixture
async def app_client(mock_redis):
    """Create a test client with mocked dependencies."""
    from main import app
    from dependencies.auth import get_redis

    app.state.redis = mock_redis
    app.dependency_overrides[get_redis] = lambda: mock_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
