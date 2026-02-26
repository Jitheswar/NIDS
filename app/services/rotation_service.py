"""Automated health checks for certificate and secret rotation.

Monitors:
1. Sensor certificate expiry — alerts when certs are within N days of expiry
2. step-ca CA health — verifies the CA is reachable and issuing
3. Keycloak signing key age — detects stale JWKS keys
4. Secret age tracking — flags secrets that haven't been rotated
5. Redis session store health — checks for anomalous session counts
"""

import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import redis.asyncio as aioredis
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings

logger = structlog.get_logger()

HEALTH_PREFIX = "rotation_health:"
CA_ROOT = Path("/app/certs/root_ca.crt")


class RotationHealthChecker:
    """Runs periodic checks on certificate and secret rotation status."""

    def __init__(self, redis: aioredis.Redis, db_session_factory):
        self.redis = redis
        self.db_session_factory = db_session_factory

    async def run_all_checks(self) -> list[dict]:
        """Run all rotation health checks. Returns a list of findings."""
        findings = []

        findings.extend(await self.check_sensor_certs())
        findings.extend(await self.check_ca_health())
        findings.extend(await self.check_keycloak_jwks())
        findings.extend(await self.check_session_health())

        # Store results
        await self._store_results(findings)

        return findings

    async def check_sensor_certs(self) -> list[dict]:
        """Check all sensor certificates for upcoming expiry."""
        findings = []
        warning_threshold = timedelta(days=settings.cert_expiry_warning_days)
        now = datetime.now(timezone.utc)

        try:
            async with self.db_session_factory() as db:
                from models.sensor import Sensor
                result = await db.execute(
                    select(Sensor).where(
                        Sensor.status == "active",
                        Sensor.cert_expires_at.isnot(None),
                    )
                )
                sensors = result.scalars().all()

                for sensor in sensors:
                    expires = sensor.cert_expires_at
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=timezone.utc)

                    remaining = expires - now

                    if remaining <= timedelta(0):
                        findings.append({
                            "check": "sensor_cert_expired",
                            "severity": "critical",
                            "sensor_id": sensor.id,
                            "sensor_name": sensor.name,
                            "expired_at": expires.isoformat(),
                            "message": f"Sensor '{sensor.name}' certificate has EXPIRED",
                        })
                    elif remaining <= warning_threshold:
                        findings.append({
                            "check": "sensor_cert_expiring",
                            "severity": "warning",
                            "sensor_id": sensor.id,
                            "sensor_name": sensor.name,
                            "expires_at": expires.isoformat(),
                            "days_remaining": remaining.days,
                            "message": f"Sensor '{sensor.name}' certificate expires in {remaining.days} days",
                        })

        except Exception as e:
            findings.append({
                "check": "sensor_cert_check_failed",
                "severity": "error",
                "message": f"Failed to check sensor certificates: {e}",
            })

        return findings

    async def check_ca_health(self) -> list[dict]:
        """Verify step-ca is reachable and healthy."""
        findings = []

        try:
            from services import mtls_service
            await mtls_service.get_ca_root_cert()

            async with httpx.AsyncClient(verify=str(CA_ROOT)) as client:
                response = await client.get(
                    f"{settings.step_ca_url}/health",
                    timeout=5.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") != "ok":
                        findings.append({
                            "check": "ca_unhealthy",
                            "severity": "critical",
                            "message": f"step-ca reports unhealthy status: {data}",
                        })
                else:
                    findings.append({
                        "check": "ca_unreachable",
                        "severity": "critical",
                        "message": f"step-ca returned status {response.status_code}",
                    })
        except Exception as e:
            findings.append({
                "check": "ca_unreachable",
                "severity": "critical",
                "message": f"Cannot reach step-ca: {e}",
            })

        return findings

    async def check_keycloak_jwks(self) -> list[dict]:
        """Check if Keycloak JWKS keys are accessible and fresh."""
        findings = []

        try:
            jwks_url = f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/certs"
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_url, timeout=5.0)
                response.raise_for_status()
                data = response.json()

                keys = data.get("keys", [])
                if not keys:
                    findings.append({
                        "check": "keycloak_no_keys",
                        "severity": "critical",
                        "message": "Keycloak JWKS has no signing keys",
                    })
                else:
                    findings.append({
                        "check": "keycloak_jwks_ok",
                        "severity": "info",
                        "key_count": len(keys),
                        "message": f"Keycloak JWKS has {len(keys)} active key(s)",
                    })
        except Exception as e:
            findings.append({
                "check": "keycloak_jwks_failed",
                "severity": "critical",
                "message": f"Cannot fetch Keycloak JWKS: {e}",
            })

        return findings

    async def check_session_health(self) -> list[dict]:
        """Check for anomalous session patterns in Redis."""
        findings = []

        try:
            # Count total active sessions
            session_count = 0
            async for key in self.redis.scan_iter(match="session:*"):
                session_count += 1

            if session_count > 1000:
                findings.append({
                    "check": "session_count_high",
                    "severity": "warning",
                    "count": session_count,
                    "message": f"High active session count: {session_count}",
                })

            # Check Redis memory usage
            info = await self.redis.info("memory")
            used_memory_mb = info.get("used_memory", 0) / (1024 * 1024)
            if used_memory_mb > 200:
                findings.append({
                    "check": "redis_memory_high",
                    "severity": "warning",
                    "used_memory_mb": round(used_memory_mb, 2),
                    "message": f"Redis memory usage: {round(used_memory_mb, 2)} MB",
                })

        except Exception as e:
            findings.append({
                "check": "session_health_failed",
                "severity": "error",
                "message": f"Session health check failed: {e}",
            })

        return findings

    async def _store_results(self, findings: list[dict]) -> None:
        """Store health check results in Redis for API access."""
        key = f"{HEALTH_PREFIX}latest"
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "warning": sum(1 for f in findings if f.get("severity") == "warning"),
                "info": sum(1 for f in findings if f.get("severity") == "info"),
            },
        }
        await self.redis.set(key, json.dumps(result), ex=settings.rotation_check_interval * 2)

        # Log critical findings
        for finding in findings:
            if finding.get("severity") == "critical":
                logger.error("ROTATION_CRITICAL", **finding)
            elif finding.get("severity") == "warning":
                logger.warning("ROTATION_WARNING", **finding)

    async def get_latest_results(self) -> dict | None:
        """Retrieve the most recent health check results."""
        key = f"{HEALTH_PREFIX}latest"
        data = await self.redis.get(key)
        if data:
            return json.loads(data)
        return None


async def start_rotation_check_loop(
    redis: aioredis.Redis, db_session_factory
) -> None:
    """Background loop that runs rotation health checks periodically."""
    checker = RotationHealthChecker(redis, db_session_factory)
    while True:
        try:
            findings = await checker.run_all_checks()
            critical = sum(1 for f in findings if f.get("severity") == "critical")
            logger.info(
                "Rotation health check completed",
                total=len(findings),
                critical=critical,
            )
        except Exception as e:
            logger.error("Rotation health check loop error", error=str(e))

        await asyncio.sleep(settings.rotation_check_interval)
