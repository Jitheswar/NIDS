import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from models.audit_log import AuditLog
from services import loki_service

logger = structlog.get_logger()


async def log_event(
    db: AsyncSession,
    event_type: str,
    actor_id: str | None,
    actor_type: str,
    ip_address: str,
    details: dict | None = None,
) -> None:
    """Write an audit log entry to the database, Loki, and structured stdout."""
    # Primary: write to database
    entry = AuditLog(
        event_type=event_type,
        actor_id=actor_id,
        actor_type=actor_type,
        ip_address=ip_address,
        details=details,
    )
    db.add(entry)
    await db.commit()

    # Secondary: push to Loki with hash-chain integrity (best-effort only)
    try:
        await loki_service.push_log(
            event_type,
            actor_id,
            actor_type,
            ip_address,
            details,
        )
    except Exception as exc:
        logger.error("Loki audit push failed", error=str(exc), event_type=event_type)

    # Structured log for fail2ban consumption
    log_data = {
        "event_type": event_type,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "ip": ip_address,
    }
    if details:
        log_data["details"] = details

    if "failure" in event_type.lower():
        logger.warning("AUTH_FAILURE", **log_data)
    else:
        logger.info("AUDIT", **log_data)
