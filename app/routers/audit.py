from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from dependencies.auth import require_role
from middleware.data_masking import apply_data_masking
from middleware.rate_limit import audit_query_rate_limit
from models.audit_log import AuditLog
from services import loki_service

router = APIRouter()


@router.get("/logs", dependencies=[Depends(audit_query_rate_limit)])
async def get_audit_logs(
    event_type: str | None = Query(None, description="Filter by event type"),
    actor_id: str | None = Query(None, description="Filter by actor ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(
        require_role("super_admin", "security_analyst", "auditor")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Query audit logs from the database. Results are masked based on user role."""
    filters = []
    if event_type:
        filters.append(AuditLog.event_type == event_type)
    if actor_id:
        filters.append(AuditLog.actor_id == actor_id)

    data_query = select(AuditLog)
    count_query = select(func.count()).select_from(AuditLog)
    for condition in filters:
        data_query = data_query.where(condition)
        count_query = count_query.where(condition)

    data_query = data_query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit)
    result = await db.execute(data_query)
    logs = result.scalars().all()
    total = (await db.execute(count_query)).scalar_one()

    log_dicts = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "event_type": log.event_type,
            "actor_id": log.actor_id,
            "actor_type": log.actor_type,
            "ip_address": log.ip_address,
            "details": log.details,
        }
        for log in logs
    ]

    # Apply data masking based on role
    masked_logs = apply_data_masking(log_dicts, current_user.get("roles", []))

    return {"logs": masked_logs, "total": total, "offset": offset, "limit": limit}


@router.get("/logs/loki", dependencies=[Depends(audit_query_rate_limit)])
async def get_loki_audit_logs(
    event_type: str | None = Query(None),
    actor_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(
        require_role("super_admin", "security_analyst", "auditor")
    ),
):
    """Query audit logs from Loki (hash-chained, append-only)."""
    logs = await loki_service.query_logs(
        event_type=event_type,
        actor_id=actor_id,
        limit=limit,
    )

    # Apply data masking
    masked_logs = apply_data_masking(logs, current_user.get("roles", []))
    return {"logs": masked_logs, "total": len(masked_logs), "source": "loki"}


@router.get("/logs/loki/verify", dependencies=[Depends(audit_query_rate_limit)])
async def verify_audit_chain(
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(require_role("super_admin")),
):
    """Verify the hash-chain integrity of Loki audit logs. Super admin only."""
    logs = await loki_service.query_logs(limit=limit)

    # Reverse to chronological order for chain verification
    logs.reverse()

    result = await loki_service.verify_chain_integrity(logs)
    return result
