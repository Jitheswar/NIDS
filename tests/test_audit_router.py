import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from database import get_db
from dependencies.auth import get_current_user
from main import app
from models.audit_log import AuditLog


class _DataResult:
    def __init__(self, logs):
        self._logs = logs

    def scalars(self):
        return self

    def all(self):
        return self._logs


class _CountResult:
    def __init__(self, total):
        self._total = total

    def scalar_one(self):
        return self._total


@pytest.mark.asyncio
async def test_audit_logs_returns_full_total_count(app_client):
    log = AuditLog(
        id=1,
        timestamp=datetime.now(timezone.utc),
        event_type="login_success",
        actor_id="user-1",
        actor_type="user",
        ip_address="10.0.0.1",
        details={},
    )

    call_count = 0

    async def execute_side_effect(_query):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _DataResult([log])
        return _CountResult(42)

    mock_db = SimpleNamespace(execute=execute_side_effect)

    async def override_db():
        yield mock_db

    async def override_current_user():
        return {"roles": ["super_admin"], "sub": "admin"}

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_current_user
    try:
        response = await app_client.get("/audit/logs?limit=1&offset=0")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 42
    assert body["limit"] == 1
    assert body["offset"] == 0
    assert len(body["logs"]) == 1
