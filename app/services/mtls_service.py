import asyncio
import json
import subprocess
import tempfile
from pathlib import Path

import structlog

from config import settings

logger = structlog.get_logger()

CERTS_DIR = Path("/app/certs")
CA_ROOT = CERTS_DIR / "root_ca.crt"


async def _run_subprocess(
    args: list[str],
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    return await asyncio.to_thread(
        subprocess.run,
        args,
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
    )


async def request_sensor_certificate(
    sensor_id: str,
    sensor_name: str,
    csr_pem: str,
) -> dict:
    """Sign a sensor CSR using step-ca and return the issued certificate."""
    await get_ca_root_cert()

    cert_path = CERTS_DIR / f"{sensor_id}.crt"
    password = settings.step_ca_password.get_secret_value()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csr", delete=False) as csr_file:
        csr_file.write(csr_pem)
        csr_path = Path(csr_file.name)

    try:
        await _run_subprocess(
            [
                "step",
                "ca",
                "sign",
                str(csr_path),
                str(cert_path),
                "--ca-url",
                settings.step_ca_url,
                "--root",
                str(CA_ROOT),
                "--provisioner",
                settings.step_ca_provisioner,
                "--provisioner-password-file",
                "/dev/stdin",
                "--not-after",
                f"{settings.cert_validity_days * 24}h",
                "--force",
            ],
            input_text=password,
        )
        logger.info("Certificate issued", sensor_id=sensor_id, sensor_name=sensor_name)
    except subprocess.CalledProcessError as e:
        logger.error("Certificate issuance failed", error=e.stderr, sensor_id=sensor_id)
        raise RuntimeError(f"Failed to issue certificate: {e.stderr}")
    finally:
        csr_path.unlink(missing_ok=True)

    cert_pem = cert_path.read_text()

    inspect_result = await _run_subprocess(
        ["step", "certificate", "inspect", str(cert_path), "--format", "json"],
    )
    cert_info = json.loads(inspect_result.stdout)
    expires_at = cert_info.get("validity", {}).get("end", "")

    return {
        "cert_pem": cert_pem,
        "expires_at": expires_at,
        "serial": cert_info.get("serial_number", ""),
    }


async def revoke_sensor_certificate(serial_number: str, reason: str = "unspecified") -> bool:
    """Revoke a sensor certificate by serial number via step-ca."""
    await get_ca_root_cert()

    try:
        await _run_subprocess(
            [
                "step",
                "ca",
                "revoke",
                serial_number,
                "--ca-url",
                settings.step_ca_url,
                "--root",
                str(CA_ROOT),
                "--provisioner",
                settings.step_ca_provisioner,
                "--provisioner-password-file",
                "/dev/stdin",
                "--reason-code",
                _reason_to_code(reason),
            ],
            input_text=settings.step_ca_password.get_secret_value(),
        )
        logger.info("Certificate revoked", serial=serial_number, reason=reason)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Certificate revocation failed", error=e.stderr, serial=serial_number)
        return False


async def renew_sensor_certificate(sensor_id: str) -> dict:
    """Renew an existing sensor certificate using the current cert+key for auth."""
    await get_ca_root_cert()

    cert_path = CERTS_DIR / f"{sensor_id}.crt"
    key_path = CERTS_DIR / f"{sensor_id}.key"

    if not cert_path.exists() or not key_path.exists():
        raise RuntimeError(f"No existing certificate for sensor {sensor_id}")

    new_cert_path = CERTS_DIR / f"{sensor_id}.new.crt"

    try:
        await _run_subprocess(
            [
                "step",
                "ca",
                "renew",
                str(cert_path),
                str(key_path),
                "--ca-url",
                settings.step_ca_url,
                "--root",
                str(CA_ROOT),
                "--out",
                str(new_cert_path),
                "--force",
            ],
        )
    except subprocess.CalledProcessError as e:
        logger.error("Certificate renewal failed", error=e.stderr, sensor_id=sensor_id)
        raise RuntimeError(f"Failed to renew certificate: {e.stderr}")

    new_cert_path.rename(cert_path)

    cert_pem = cert_path.read_text()
    inspect_result = await _run_subprocess(
        ["step", "certificate", "inspect", str(cert_path), "--format", "json"],
    )
    cert_info = json.loads(inspect_result.stdout)

    logger.info("Certificate renewed", sensor_id=sensor_id)
    return {
        "cert_pem": cert_pem,
        "expires_at": cert_info.get("validity", {}).get("end", ""),
        "serial": cert_info.get("serial_number", ""),
    }


async def get_ca_root_cert() -> str:
    """Return the CA root certificate PEM for sensor trust bootstrapping."""
    if CA_ROOT.exists():
        return CA_ROOT.read_text()

    fingerprint = settings.step_ca_fingerprint.strip()
    if not fingerprint:
        raise RuntimeError(
            "STEP_CA_FINGERPRINT must be configured before initial step-ca bootstrap"
        )

    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        await _run_subprocess(
            [
                "step",
                "ca",
                "root",
                str(CA_ROOT),
                "--ca-url",
                settings.step_ca_url,
                "--fingerprint",
                fingerprint,
            ],
        )
        return CA_ROOT.read_text()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to fetch CA root: {e.stderr}")


def _reason_to_code(reason: str) -> str:
    """Map revocation reason to RFC 5280 reason code."""
    reasons = {
        "unspecified": "0",
        "key_compromise": "1",
        "ca_compromise": "2",
        "affiliation_changed": "3",
        "superseded": "4",
        "cessation_of_operation": "5",
    }
    return reasons.get(reason, "0")
