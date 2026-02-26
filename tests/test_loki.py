import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.loki_service import _compute_chain_hash, query_logs, verify_chain_integrity


def test_chain_hash_deterministic():
    entry = {"event_type": "login", "actor_id": "user1", "ip_address": "10.0.0.1"}
    prev = "0" * 64

    h1 = _compute_chain_hash(entry, prev)
    h2 = _compute_chain_hash(entry, prev)
    assert h1 == h2


def test_chain_hash_changes_with_data():
    entry1 = {"event_type": "login", "actor_id": "user1"}
    entry2 = {"event_type": "logout", "actor_id": "user1"}
    prev = "0" * 64

    h1 = _compute_chain_hash(entry1, prev)
    h2 = _compute_chain_hash(entry2, prev)
    assert h1 != h2


def test_chain_hash_changes_with_previous():
    entry = {"event_type": "login", "actor_id": "user1"}

    h1 = _compute_chain_hash(entry, "a" * 64)
    h2 = _compute_chain_hash(entry, "b" * 64)
    assert h1 != h2


@pytest.mark.asyncio
async def test_verify_empty_chain():
    result = await verify_chain_integrity([])
    assert result["valid"] is True
    assert result["total"] == 0


@pytest.mark.asyncio
async def test_verify_valid_chain():
    prev = "0" * 64
    entry1_data = {"event_type": "login", "actor_id": "u1", "actor_type": "user", "ip_address": "10.0.0.1", "details": {}}
    h1 = _compute_chain_hash(entry1_data, prev)
    entry1 = {**entry1_data, "chain_hash": h1, "previous_hash": prev}

    entry2_data = {"event_type": "logout", "actor_id": "u1", "actor_type": "user", "ip_address": "10.0.0.1", "details": {}}
    h2 = _compute_chain_hash(entry2_data, h1)
    entry2 = {**entry2_data, "chain_hash": h2, "previous_hash": h1}

    result = await verify_chain_integrity([entry1, entry2])
    assert result["valid"] is True
    assert result["total"] == 2


@pytest.mark.asyncio
async def test_verify_broken_chain():
    prev = "0" * 64
    entry1_data = {"event_type": "login", "actor_id": "u1", "actor_type": "user", "ip_address": "10.0.0.1", "details": {}}
    h1 = _compute_chain_hash(entry1_data, prev)
    entry1 = {**entry1_data, "chain_hash": h1, "previous_hash": prev}

    # Tampered entry — wrong previous_hash
    entry2 = {
        "event_type": "logout", "actor_id": "u1", "actor_type": "user",
        "ip_address": "10.0.0.1", "details": {},
        "chain_hash": "fake_hash",
        "previous_hash": "wrong_previous",
    }

    result = await verify_chain_integrity([entry1, entry2])
    assert result["valid"] is False
    assert result["broken_at"] == 1


@pytest.mark.asyncio
async def test_query_logs_actor_id_uses_json_pipeline():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"data": {"result": []}}

    client = AsyncMock()
    client.get = AsyncMock(return_value=response)

    client_context = AsyncMock()
    client_context.__aenter__.return_value = client
    client_context.__aexit__.return_value = None

    with patch("services.loki_service.httpx.AsyncClient", return_value=client_context):
        await query_logs(event_type="login_success", actor_id='user"1', limit=25)

    called_params = client.get.await_args.kwargs["params"]
    query = called_params["query"]
    assert query.startswith('{job="nids-audit",event_type="login_success"}')
    assert '| json | actor_id="user\\"1"' in query


@pytest.mark.asyncio
async def test_verify_chain_detects_restart_boundary_reset():
    genesis = "0" * 64
    entry1_data = {"event_type": "event_a", "actor_id": "u1", "actor_type": "user", "ip_address": "10.0.0.1", "details": {}}
    h1 = _compute_chain_hash(entry1_data, genesis)
    entry1 = {**entry1_data, "chain_hash": h1, "previous_hash": genesis}

    # Simulate a restart writing a new log with previous_hash reset to genesis.
    entry2_data = {"event_type": "event_b", "actor_id": "u1", "actor_type": "user", "ip_address": "10.0.0.1", "details": {}}
    h2 = _compute_chain_hash(entry2_data, genesis)
    entry2 = {**entry2_data, "chain_hash": h2, "previous_hash": genesis}

    result = await verify_chain_integrity([entry1, entry2])
    assert result["valid"] is False
    assert result["broken_at"] == 1
