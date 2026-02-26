import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from dependencies.auth import get_current_user
from main import app


@pytest.mark.asyncio
async def test_login_refresh_logout_flow(app_client):
    token_payload = {
        "sub": "user-1",
        "preferred_username": "alice",
        "sid": "kc-session-1",
        "realm_access": {"roles": ["security_analyst"]},
    }

    async def override_current_user():
        return {
            "sub": "user-1",
            "username": "alice",
            "session_id": "kc-session-1",
            "roles": ["security_analyst"],
            "iat": 123456,
        }

    with patch("routers.auth.lockout_service.check_lockout", new=AsyncMock(return_value={"locked": False})):
        with patch(
            "routers.auth.keycloak_service.authenticate",
            new=AsyncMock(
                return_value={
                    "access_token": "access-1",
                    "refresh_token": "refresh-1",
                    "expires_in": 900,
                }
            ),
        ):
            with patch("routers.auth.keycloak_service.decode_token", new=AsyncMock(return_value=token_payload)):
                with patch("routers.auth.session_service.create_session", new=AsyncMock(return_value="kc-session-1")):
                    with patch("routers.auth.lockout_service.reset_on_success", new=AsyncMock()):
                        with patch("routers.auth.audit_service.log_event", new=AsyncMock()):
                            with patch("routers.auth.AnomalyDetector.analyze_event", new=AsyncMock(return_value=[])):
                                login_response = await app_client.post(
                                    "/auth/login",
                                    json={"username": "alice", "password": "SecretPass123!"},
                                )

    assert login_response.status_code == 200
    login_body = login_response.json()
    assert login_body["access_token"] == "access-1"

    app.dependency_overrides[get_current_user] = override_current_user
    try:
        with patch("routers.auth.session_service.get_refresh_token", new=AsyncMock(return_value="refresh-1")):
            with patch(
                "routers.auth.keycloak_service.refresh_token",
                new=AsyncMock(
                    return_value={
                        "access_token": "access-2",
                        "refresh_token": "refresh-2",
                        "expires_in": 900,
                    }
                ),
            ):
                with patch("routers.auth.session_service.update_session_tokens", new=AsyncMock(return_value=True)):
                    with patch("routers.auth.audit_service.log_event", new=AsyncMock()):
                        refresh_response = await app_client.post("/auth/refresh")

        assert refresh_response.status_code == 200
        assert refresh_response.json()["access_token"] == "access-2"

        with patch("routers.auth.session_service.get_refresh_token", new=AsyncMock(return_value="refresh-2")):
            with patch("routers.auth.keycloak_service.logout_token", new=AsyncMock()):
                with patch("routers.auth.session_service.revoke_session", new=AsyncMock(return_value=True)):
                    with patch("routers.auth.audit_service.log_event", new=AsyncMock()):
                        logout_response = await app_client.post("/auth/logout")

        assert logout_response.status_code == 204
    finally:
        app.dependency_overrides.pop(get_current_user, None)
