import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.audit_service import log_event


@pytest.mark.asyncio
async def test_log_event_persists_even_if_loki_fails():
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    with patch(
        "services.audit_service.loki_service.push_log",
        new=AsyncMock(side_effect=RuntimeError("loki down")),
    ):
        await log_event(
            db=db,
            event_type="login_success",
            actor_id="user-1",
            actor_type="user",
            ip_address="10.0.0.1",
            details={"username": "alice"},
        )

    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.rollback.assert_not_awaited()
