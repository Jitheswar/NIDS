import hashlib
import json
import time

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import async_session
from models.audit_chain_state import AuditChainState

logger = structlog.get_logger()

GENESIS_HASH = "0" * 64


def _compute_chain_hash(entry: dict, previous: str) -> str:
    """Compute SHA-256 hash chaining this entry to the previous one."""
    payload = json.dumps(entry, sort_keys=True) + previous
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def _get_chain_state_for_update(db: AsyncSession) -> AuditChainState:
    stmt = select(AuditChainState).where(AuditChainState.id == 1).with_for_update()
    result = await db.execute(stmt)
    state = result.scalar_one_or_none()
    if state:
        return state

    state = AuditChainState(id=1, previous_hash=GENESIS_HASH)
    db.add(state)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        result = await db.execute(stmt)
        state = result.scalar_one()
    return state


async def push_log(
    event_type: str,
    actor_id: str | None,
    actor_type: str,
    ip_address: str,
    details: dict | None = None,
) -> None:
    """Push an audit log entry to Loki with hash-chain integrity.

    Each entry includes:
    - The log data itself
    - A SHA-256 hash linking it to the previous entry (tamper detection)
    """
    timestamp_ns = str(int(time.time() * 1e9))

    entry = {
        "event_type": event_type,
        "actor_id": actor_id or "",
        "actor_type": actor_type,
        "ip_address": ip_address,
        "details": details or {},
    }

    async with async_session() as db:
        try:
            state = await _get_chain_state_for_update(db)
            previous_hash = state.previous_hash or GENESIS_HASH
        except Exception as e:
            logger.error("Failed to fetch audit chain state", error=str(e))
            return

        chain_hash = _compute_chain_hash(entry, previous_hash)
        entry["chain_hash"] = chain_hash
        entry["previous_hash"] = previous_hash

        log_line = json.dumps(entry, sort_keys=True)

        payload = {
            "streams": [
                {
                    "stream": {
                        "job": "nids-audit",
                        "event_type": event_type,
                        "actor_type": actor_type,
                    },
                    "values": [[timestamp_ns, log_line]],
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.loki_url}/loki/api/v1/push",
                    json=payload,
                    timeout=5.0,
                )
                response.raise_for_status()
                state.previous_hash = chain_hash
                await db.commit()
        except Exception as e:
            await db.rollback()
            # Log failure but don't block the request — audit is best-effort to Loki,
            # DB audit_log is the primary record
            logger.error("Failed to push audit log to Loki", error=str(e))


def _escape_logql_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


async def query_logs(
    event_type: str | None = None,
    actor_id: str | None = None,
    limit: int = 100,
    start_ns: str | None = None,
    end_ns: str | None = None,
) -> list[dict]:
    """Query audit logs from Loki."""
    label_parts = ['job="nids-audit"']
    if event_type:
        label_parts.append(f'event_type="{_escape_logql_value(event_type)}"')

    query = "{" + ",".join(label_parts) + "}"
    if actor_id:
        query += f' | json | actor_id="{_escape_logql_value(actor_id)}"'

    params = {"query": query, "limit": str(limit), "direction": "backward"}
    if start_ns:
        params["start"] = start_ns
    if end_ns:
        params["end"] = end_ns

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.loki_url}/loki/api/v1/query_range",
                params=params,
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()

            results = []
            for stream in data.get("data", {}).get("result", []):
                for ts, line in stream.get("values", []):
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        results.append({"raw": line})
            return results
    except Exception as e:
        logger.error("Failed to query Loki", error=str(e))
        return []


async def verify_chain_integrity(logs: list[dict]) -> dict:
    """Verify the hash chain integrity of a list of audit log entries.
    Entries should be in chronological order (oldest first).
    Returns {"valid": bool, "broken_at": int | None, "total": int}
    """
    if not logs:
        return {"valid": True, "broken_at": None, "total": 0}

    for i, entry in enumerate(logs):
        if i == 0:
            continue

        previous_entry = logs[i - 1]
        expected_previous_hash = previous_entry.get("chain_hash", "")
        actual_previous_hash = entry.get("previous_hash", "")

        if expected_previous_hash != actual_previous_hash:
            return {"valid": False, "broken_at": i, "total": len(logs)}

        # Verify the entry's own hash
        entry_data = {k: v for k, v in entry.items() if k not in ("chain_hash", "previous_hash")}
        computed = _compute_chain_hash(entry_data, actual_previous_hash)
        if computed != entry.get("chain_hash"):
            return {"valid": False, "broken_at": i, "total": len(logs)}

    return {"valid": True, "broken_at": None, "total": len(logs)}
