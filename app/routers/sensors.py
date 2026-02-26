import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from config import settings
from database import get_db
from dependencies.auth import require_role, verify_sensor_mtls
from middleware.rate_limit import (
    auth_general_rate_limit,
    sensor_activate_rate_limit,
    sensor_enroll_rate_limit,
    sensor_mutation_rate_limit,
)
from schemas.api_key import ApiKeyResponse, SensorActivateRequest, SensorActivateResponse
from schemas.sensor import (
    SensorCertIssueRequest,
    SensorCertResponse,
    SensorCertRevokeRequest,
    SensorCreate,
    SensorListResponse,
    SensorResponse,
)
from services import audit_service, sensor_service
from utils.network import get_client_ip

logger = structlog.get_logger()

router = APIRouter()


@router.post(
    "/",
    response_model=SensorResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(sensor_mutation_rate_limit)],
)
async def create_sensor(
    body: SensorCreate,
    request: Request,
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """Register a new sensor."""
    ip = get_client_ip(request)

    try:
        sensor = await sensor_service.create_sensor(
            db, body.name, body.network_segment, current_user["sub"]
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await audit_service.log_event(
        db, "sensor_created", current_user["sub"], "user", ip,
        {"sensor_id": sensor.id, "sensor_name": sensor.name},
    )

    return sensor


@router.post(
    "/{sensor_id}/enroll",
    response_model=ApiKeyResponse,
    dependencies=[Depends(sensor_enroll_rate_limit)],
)
async def enroll_sensor(
    sensor_id: str,
    request: Request,
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """Generate a single-use enrollment API key for a sensor."""
    ip = get_client_ip(request)

    try:
        raw_key, api_key = await sensor_service.generate_enrollment_key(
            db, sensor_id, current_user["sub"]
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await audit_service.log_event(
        db, "api_key_generated", current_user["sub"], "user", ip,
        {"sensor_id": sensor_id},
    )

    return ApiKeyResponse(
        api_key=raw_key,
        sensor_id=sensor_id,
        expires_at=api_key.expires_at,
    )


@router.post(
    "/activate",
    response_model=SensorActivateResponse,
    dependencies=[Depends(sensor_activate_rate_limit)],
)
async def activate_sensor(
    body: SensorActivateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Activate a sensor using its enrollment API key. No auth required (key is the auth)."""
    ip = get_client_ip(request)

    try:
        sensor = await sensor_service.activate_sensor(db, body.api_key)
    except ValueError as e:
        await audit_service.log_event(
            db, "sensor_activation_failure", None, "sensor", ip,
            {"error": str(e)},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await audit_service.log_event(
        db, "sensor_activated", sensor.id, "sensor", ip,
        {"sensor_name": sensor.name},
    )

    return SensorActivateResponse(
        sensor_id=sensor.id,
        status=sensor.status,
        message="Sensor activated successfully",
    )


@router.get(
    "/",
    response_model=SensorListResponse,
    dependencies=[Depends(auth_general_rate_limit)],
)
async def list_sensors(
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """List all sensors."""
    sensors = await sensor_service.list_sensors(db)
    return SensorListResponse(
        sensors=[SensorResponse.model_validate(s) for s in sensors],
        total=len(sensors),
    )


@router.delete(
    "/{sensor_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(sensor_mutation_rate_limit)],
)
async def disable_sensor(
    sensor_id: str,
    request: Request,
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """Disable a sensor and revoke its certificate if mTLS is enabled."""
    ip = get_client_ip(request)

    try:
        sensor = await sensor_service.disable_sensor(db, sensor_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # Revoke certificate if mTLS is enabled and sensor has a cert
    if settings.mtls_enabled and sensor.cert_serial:
        from services import mtls_service, crl_service
        revoked = await mtls_service.revoke_sensor_certificate(
            sensor.cert_serial, reason="cessation_of_operation"
        )
        if revoked:
            crl_service.add_to_revoked(sensor.cert_serial)

    await audit_service.log_event(
        db, "sensor_disabled", current_user["sub"], "user", ip,
        {"sensor_id": sensor_id, "sensor_name": sensor.name},
    )

    return {"message": f"Sensor '{sensor.name}' has been disabled"}


# --- Phase 2: mTLS Certificate Management ---


@router.post(
    "/{sensor_id}/certificate",
    response_model=SensorCertResponse,
    dependencies=[Depends(sensor_mutation_rate_limit)],
)
async def issue_sensor_certificate(
    sensor_id: str,
    body: SensorCertIssueRequest,
    request: Request,
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """Issue an mTLS certificate for an active sensor via step-ca."""
    ip = get_client_ip(request)

    if not settings.mtls_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="mTLS is not enabled. Set MTLS_ENABLED=true.",
        )

    sensor = await sensor_service.get_sensor(db, sensor_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")
    if sensor.status != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sensor must be active (current: {sensor.status})",
        )

    from services import mtls_service
    try:
        cert_data = await mtls_service.request_sensor_certificate(
            sensor.id,
            sensor.name,
            body.csr_pem,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    # Update sensor with cert info
    sensor.cert_serial = cert_data["serial"]
    sensor.cert_expires_at = datetime.fromisoformat(cert_data["expires_at"].replace("Z", "+00:00")) if cert_data["expires_at"] else None
    sensor.cert_issued_at = datetime.now(timezone.utc)
    await db.commit()

    ca_pem = await mtls_service.get_ca_root_cert()

    await audit_service.log_event(
        db, "sensor_cert_issued", current_user["sub"], "user", ip,
        {"sensor_id": sensor_id, "serial": cert_data["serial"]},
    )

    return SensorCertResponse(
        sensor_id=sensor_id,
        cert_pem=cert_data["cert_pem"],
        ca_pem=ca_pem,
        expires_at=cert_data["expires_at"],
        serial=cert_data["serial"],
    )


@router.post(
    "/{sensor_id}/certificate/revoke",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(sensor_mutation_rate_limit)],
)
async def revoke_sensor_certificate(
    sensor_id: str,
    body: SensorCertRevokeRequest,
    request: Request,
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a sensor's mTLS certificate."""
    ip = get_client_ip(request)

    sensor = await sensor_service.get_sensor(db, sensor_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")
    if not sensor.cert_serial:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sensor has no certificate to revoke",
        )

    from services import mtls_service, crl_service
    revoked = await mtls_service.revoke_sensor_certificate(sensor.cert_serial, body.reason)

    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke certificate",
        )

    # Immediately update in-memory CRL
    crl_service.add_to_revoked(sensor.cert_serial)

    # Clear cert info from sensor
    old_serial = sensor.cert_serial
    sensor.cert_serial = None
    sensor.cert_expires_at = None
    await db.commit()

    await audit_service.log_event(
        db, "sensor_cert_revoked", current_user["sub"], "user", ip,
        {"sensor_id": sensor_id, "serial": old_serial, "reason": body.reason},
    )

    return {"message": f"Certificate {old_serial} revoked", "sensor_id": sensor_id}


@router.post(
    "/{sensor_id}/certificate/renew",
    response_model=SensorCertResponse,
    dependencies=[Depends(sensor_mutation_rate_limit)],
)
async def renew_sensor_certificate(
    sensor_id: str,
    request: Request,
    current_user: dict = Depends(require_role("super_admin", "sensor_manager")),
    db: AsyncSession = Depends(get_db),
):
    """Renew an existing sensor certificate."""
    ip = get_client_ip(request)

    sensor = await sensor_service.get_sensor(db, sensor_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")
    if not sensor.cert_serial:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sensor has no certificate to renew. Issue one first.",
        )

    from services import mtls_service
    try:
        cert_data = await mtls_service.renew_sensor_certificate(sensor.id)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    sensor.cert_serial = cert_data["serial"]
    sensor.cert_expires_at = datetime.fromisoformat(cert_data["expires_at"].replace("Z", "+00:00")) if cert_data["expires_at"] else None
    sensor.cert_issued_at = datetime.now(timezone.utc)
    await db.commit()

    ca_pem = await mtls_service.get_ca_root_cert()

    await audit_service.log_event(
        db, "sensor_cert_renewed", current_user["sub"], "user", ip,
        {"sensor_id": sensor_id, "serial": cert_data["serial"]},
    )

    return SensorCertResponse(
        sensor_id=sensor_id,
        cert_pem=cert_data.get("cert_pem", ""),
        ca_pem=ca_pem,
        expires_at=cert_data["expires_at"],
        serial=cert_data["serial"],
    )


# --- Phase 2: mTLS-authenticated sensor data endpoint ---


@router.post(
    "/data",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(auth_general_rate_limit)],
)
async def submit_sensor_data(
    request: Request,
    sensor_identity: dict = Depends(verify_sensor_mtls),
    db: AsyncSession = Depends(get_db),
):
    """Receive data from a sensor authenticated via mTLS client certificate.
    This is the endpoint sensors use to submit network traffic data.
    """
    ip = get_client_ip(request)
    body = await request.json()

    await audit_service.log_event(
        db, "sensor_data_received", sensor_identity["cn"], "sensor", ip,
        {"serial": sensor_identity["serial"]},
    )

    return {"status": "accepted", "sensor": sensor_identity["cn"]}
