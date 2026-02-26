"""Phase 3 API endpoints: anomaly alerts, ZTNA status, and rotation health checks."""

from fastapi import APIRouter, Depends, Query, Request

from database import async_session
from dependencies.auth import get_current_user, get_redis, require_role
from middleware.rate_limit import security_mutation_rate_limit, security_read_rate_limit
from services.anomaly_service import AnomalyDetector
from services.rotation_service import RotationHealthChecker

router = APIRouter()


# --- Anomaly Detection ---


@router.get("/anomalies", dependencies=[Depends(security_read_rate_limit)])
async def get_anomaly_alerts(
    severity: str | None = Query(None, description="Filter: low, medium, high"),
    alert_type: str | None = Query(None, description="Filter: credential_stuffing, impossible_travel, etc."),
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(
        require_role("super_admin", "security_analyst")
    ),
    redis=Depends(get_redis),
):
    """List recent anomaly detection alerts."""
    detector = AnomalyDetector(redis)
    alerts = await detector.get_alerts(
        severity=severity,
        alert_type=alert_type,
        limit=limit,
    )
    return {
        "alerts": alerts,
        "total": len(alerts),
    }


@router.get("/anomalies/risk-score", dependencies=[Depends(security_read_rate_limit)])
async def get_risk_score(
    username: str | None = Query(None),
    ip: str | None = Query(None),
    current_user: dict = Depends(
        require_role("super_admin", "security_analyst")
    ),
    redis=Depends(get_redis),
):
    """Get the risk score for a user or IP based on anomaly detection."""
    if not username and not ip:
        return {"error": "Provide at least one of: username, ip"}

    detector = AnomalyDetector(redis)
    return await detector.get_risk_score(username=username, ip=ip)


# --- Rotation Health Checks ---


@router.get("/rotation-health", dependencies=[Depends(security_read_rate_limit)])
async def get_rotation_health(
    current_user: dict = Depends(require_role("super_admin")),
    redis=Depends(get_redis),
):
    """Get the latest rotation health check results."""
    checker = RotationHealthChecker(redis, async_session)
    results = await checker.get_latest_results()
    if results:
        return results
    return {"message": "No health check results yet. Checks run periodically."}


@router.post("/rotation-health/run", dependencies=[Depends(security_mutation_rate_limit)])
async def run_rotation_health_check(
    current_user: dict = Depends(require_role("super_admin")),
    redis=Depends(get_redis),
):
    """Manually trigger a rotation health check (super_admin only)."""
    checker = RotationHealthChecker(redis, async_session)
    findings = await checker.run_all_checks()
    return {
        "findings": findings,
        "total": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "warning": sum(1 for f in findings if f.get("severity") == "warning"),
    }


# --- ZTNA Status ---


@router.get("/ztna/status", dependencies=[Depends(security_read_rate_limit)])
async def get_ztna_status(
    current_user: dict = Depends(require_role("super_admin")),
):
    """Get the current ZTNA configuration status."""
    from config import settings

    return {
        "enabled": settings.ztna_enabled,
        "require_device_id": settings.ztna_require_device_id,
        "allowed_user_agents": settings.ztna_allowed_user_agents or "(all allowed)",
        "geo_allowlist": settings.ztna_geo_allowlist or "(all allowed)",
        "risk_score_threshold": settings.ztna_risk_score_threshold,
    }


@router.get("/ztna/context", dependencies=[Depends(security_read_rate_limit)])
async def get_request_ztna_context(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Get the ZTNA trust context for the current request."""
    context = getattr(request.state, "ztna_context", None)
    if context:
        return {"ztna_applied": True, "context": context}
    return {"ztna_applied": False, "message": "ZTNA is not enabled"}
