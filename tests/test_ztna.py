import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


def test_ztna_exempt_paths():
    """ZTNA should not apply to exempt paths."""
    from middleware.ztna import EXEMPT_PATHS
    assert "/health" in EXEMPT_PATHS
    assert "/health/live" in EXEMPT_PATHS
    assert "/health/ready" in EXEMPT_PATHS
    assert "/auth/login" in EXEMPT_PATHS
    assert "/sensors/activate" in EXEMPT_PATHS


@pytest.mark.asyncio
async def test_health_accessible_with_ztna(app_client):
    """Health endpoint should work even with ZTNA (exempt)."""
    response = await app_client.get("/health/live")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_security_endpoints_require_auth(app_client):
    """Security endpoints should require auth."""
    response = await app_client.get("/security/anomalies")
    assert response.status_code == 401

    response = await app_client.get("/security/rotation-health")
    assert response.status_code == 401

    response = await app_client.get("/security/ztna/status")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ztna_fails_closed_when_risk_check_errors():
    """Risk-check internal failures should deny traffic."""
    from middleware.ztna import ZTNAMiddleware

    middleware = ZTNAMiddleware(app=AsyncMock())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=AsyncMock())))
    context = {
        "ip": "10.0.0.10",
        "user_agent": "test-client",
        "device_id": "",
    }

    with patch(
        "services.anomaly_service.AnomalyDetector.get_risk_score",
        new=AsyncMock(side_effect=Exception("redis-down")),
    ):
        decision = await middleware._evaluate_trust(context, request)

    assert decision["allow"] is False
    assert decision["status_code"] == 503
    assert decision["reason"] == "risk_check_unavailable"
