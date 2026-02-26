import asyncio
import time
from pathlib import Path

import httpx
import structlog

from config import settings

logger = structlog.get_logger()

CRL_DIR = Path("/app/crl")
CRL_FILE = CRL_DIR / "nids.crl"
CA_ROOT = Path("/app/certs/root_ca.crt")

# In-memory set of revoked serial numbers for fast lookup
_revoked_serials: set[str] = set()
_crl_last_refreshed: float = 0


async def refresh_crl() -> None:
    """Fetch the latest CRL from step-ca and update the in-memory revoked set."""
    global _revoked_serials, _crl_last_refreshed

    try:
        from services import mtls_service
        await mtls_service.get_ca_root_cert()

        # step-ca serves CRL at /1.0/crl
        async with httpx.AsyncClient(verify=str(CA_ROOT)) as client:
            response = await client.get(
                f"{settings.step_ca_url}/1.0/crl",
                timeout=10.0,
            )
            response.raise_for_status()

        CRL_DIR.mkdir(parents=True, exist_ok=True)
        CRL_FILE.write_bytes(response.content)

        # Parse CRL to extract revoked serial numbers
        from cryptography.x509 import load_der_x509_crl

        crl = load_der_x509_crl(response.content)
        new_serials = set()
        for revoked in crl:
            new_serials.add(format(revoked.serial_number, "x").lower())

        _revoked_serials = new_serials
        _crl_last_refreshed = time.time()

        logger.info("CRL refreshed", revoked_count=len(_revoked_serials))

    except Exception as e:
        logger.error("CRL refresh failed", error=str(e))


def is_certificate_revoked(serial_number: str) -> bool:
    """Check if a certificate serial number is in the revoked set."""
    return serial_number.lower() in _revoked_serials


async def start_crl_refresh_loop() -> None:
    """Background task that periodically refreshes the CRL."""
    while True:
        await refresh_crl()
        await asyncio.sleep(settings.crl_refresh_interval)


def add_to_revoked(serial_number: str) -> None:
    """Immediately add a serial to the in-memory revoked set (before CRL refresh)."""
    _revoked_serials.add(serial_number.lower())
    logger.info("Serial added to in-memory CRL", serial=serial_number)
