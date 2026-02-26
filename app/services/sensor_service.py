from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.sensor import Sensor
from models.api_key import ApiKey
from utils.crypto import generate_api_key, hash_api_key


async def create_sensor(
    db: AsyncSession,
    name: str,
    network_segment: str,
    created_by: str,
) -> Sensor:
    """Register a new sensor."""
    sensor = Sensor(
        name=name,
        network_segment=network_segment,
        status="pending",
        created_by=created_by,
    )
    db.add(sensor)
    await db.commit()
    await db.refresh(sensor)
    return sensor


async def generate_enrollment_key(
    db: AsyncSession,
    sensor_id: str,
    created_by: str,
) -> tuple[str, ApiKey]:
    """Generate a single-use API key for sensor enrollment.
    Returns (raw_key, api_key_record).
    """
    # Verify sensor exists and is pending
    sensor = await db.get(Sensor, sensor_id)
    if not sensor:
        raise ValueError("Sensor not found")
    if sensor.status != "pending":
        raise ValueError(f"Sensor is already {sensor.status}")

    raw_key = generate_api_key(settings.api_key_length)
    key_hash = hash_api_key(raw_key)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.api_key_expiry)

    api_key = ApiKey(
        sensor_id=sensor_id,
        key_hash=key_hash,
        expires_at=expires_at,
        used=False,
        created_by=created_by,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return raw_key, api_key


async def activate_sensor(db: AsyncSession, raw_key: str) -> Sensor:
    """Activate a sensor using its enrollment API key.
    The key is marked as used after activation.
    """
    key_hash = hash_api_key(raw_key)

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_hash == key_hash,
            ApiKey.used == False,  # noqa: E712
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise ValueError("Invalid or already used API key")

    now = datetime.now(timezone.utc)
    if api_key.expires_at.replace(tzinfo=timezone.utc) < now:
        raise ValueError("API key has expired")

    # Mark key as used
    api_key.used = True
    api_key.used_at = now

    # Activate the sensor
    sensor = await db.get(Sensor, api_key.sensor_id)
    if not sensor:
        raise ValueError("Associated sensor not found")

    sensor.status = "active"
    sensor.activated_at = now

    await db.commit()
    await db.refresh(sensor)
    return sensor


async def list_sensors(db: AsyncSession) -> list[Sensor]:
    """List all sensors."""
    result = await db.execute(select(Sensor).order_by(Sensor.created_at.desc()))
    return list(result.scalars().all())


async def get_sensor(db: AsyncSession, sensor_id: str) -> Sensor | None:
    """Get a sensor by ID."""
    return await db.get(Sensor, sensor_id)


async def disable_sensor(db: AsyncSession, sensor_id: str) -> Sensor:
    """Disable a sensor."""
    sensor = await db.get(Sensor, sensor_id)
    if not sensor:
        raise ValueError("Sensor not found")

    sensor.status = "disabled"
    await db.commit()
    await db.refresh(sensor)
    return sensor
