import time as _time

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from keycloak.exceptions import KeycloakAuthenticationError
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from dependencies.auth import get_current_user, get_redis, require_role
from middleware.rate_limit import auth_general_rate_limit, login_rate_limit
from schemas.auth import LoginRequest, TokenResponse, UnlockRequest, UserInfo
from services import audit_service, keycloak_service, lockout_service, session_service, token_revocation_service
from services.anomaly_service import AnomalyDetector
from utils.network import get_client_ip

logger = structlog.get_logger()

router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(login_rate_limit)],
)
async def login(
    body: LoginRequest,
    request: Request,
    redis=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user via Keycloak. Enforces lockout policy."""
    ip = get_client_ip(request)
    username = body.username

    # Check lockout
    lockout = await lockout_service.check_lockout(redis, username)
    if lockout["locked"]:
        await audit_service.log_event(
            db, "login_blocked", None, "system", ip,
            {"username": username, "permanent": lockout["permanent"]},
        )
        if lockout["permanent"]:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account permanently locked. Contact an administrator.",
            )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account temporarily locked. Try again in {lockout['remaining']} seconds.",
        )

    # Authenticate with Keycloak
    try:
        tokens = await keycloak_service.authenticate(
            username, body.password.get_secret_value()
        )
    except KeycloakAuthenticationError:
        lockout_result = await lockout_service.record_failure(redis, username)
        await audit_service.log_event(
            db, "login_failure", None, "user", ip, {"username": username},
        )

        # Phase 3: Anomaly detection on failure
        detector = AnomalyDetector(redis)
        await detector.analyze_event({
            "event_type": "login_failure",
            "actor_id": None,
            "ip_address": ip,
            "username": username,
            "timestamp": _time.time(),
        })

        if lockout_result["locked"]:
            detail = "Account locked. Contact an administrator." if lockout_result["permanent"] else "Too many failed attempts. Account temporarily locked."
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=detail)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Decode token to get user info
    payload = await keycloak_service.decode_token(tokens["access_token"])
    user_id = payload["sub"]
    session_id = keycloak_service.extract_session_id(payload)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token session claims",
        )

    # Create session in Redis
    await session_service.create_session(
        redis,
        user_id,
        session_id,
        tokens["refresh_token"],
    )

    # Clear lockout on success
    await lockout_service.reset_on_success(redis, username)

    # Audit log
    await audit_service.log_event(
        db, "login_success", user_id, "user", ip, {"username": username},
    )

    # Phase 3: Anomaly detection on success
    detector = AnomalyDetector(redis)
    await detector.analyze_event({
        "event_type": "login_success",
        "actor_id": user_id,
        "ip_address": ip,
        "username": username,
        "timestamp": _time.time(),
    })

    return TokenResponse(
        access_token=tokens["access_token"],
        expires_in=tokens["expires_in"],
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(auth_general_rate_limit)],
)
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    redis=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
):
    """Logout: revoke session and refresh token."""
    ip = get_client_ip(request)
    user_id = current_user["sub"]
    session_id = current_user["session_id"]

    # Get refresh token from session before revoking
    refresh = await session_service.get_refresh_token(redis, user_id, session_id)
    if refresh:
        try:
            await keycloak_service.logout_token(refresh)
        except Exception:
            logger.warning("Failed to revoke refresh token in Keycloak", user_id=user_id)

    # Revoke Redis session
    await session_service.revoke_session(redis, user_id, session_id)

    await audit_service.log_event(
        db, "logout", user_id, "user", ip,
        {"username": current_user["username"]},
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(auth_general_rate_limit)],
)
async def refresh_token(
    request: Request,
    current_user: dict = Depends(get_current_user),
    redis=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
):
    """Exchange refresh token for new access token."""
    ip = get_client_ip(request)
    user_id = current_user["sub"]
    session_id = current_user["session_id"]

    refresh = await session_service.get_refresh_token(redis, user_id, session_id)
    if not refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No valid session found",
        )

    try:
        tokens = await keycloak_service.refresh_token(refresh)
    except Exception:
        await session_service.revoke_session(redis, user_id, session_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired. Please login again.",
        )

    # Update session with new refresh token
    await session_service.update_session_tokens(
        redis, user_id, session_id, tokens["refresh_token"]
    )

    await audit_service.log_event(
        db, "token_refresh", user_id, "user", ip,
        {"username": current_user["username"]},
    )

    return TokenResponse(
        access_token=tokens["access_token"],
        expires_in=tokens["expires_in"],
    )


@router.get("/me", response_model=UserInfo)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Return current user info from JWT claims."""
    return UserInfo(
        sub=current_user["sub"],
        username=current_user["username"],
        email=current_user.get("email"),
        first_name=current_user.get("first_name"),
        last_name=current_user.get("last_name"),
        roles=current_user.get("roles", []),
    )


@router.post(
    "/unlock",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(auth_general_rate_limit)],
)
async def unlock_account(
    body: UnlockRequest,
    request: Request,
    current_user: dict = Depends(require_role("super_admin")),
    redis=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
):
    """Unlock a permanently locked account. Requires super_admin role."""
    ip = get_client_ip(request)
    unlocked = await lockout_service.unlock_account(redis, body.username)

    await audit_service.log_event(
        db, "account_unlock", current_user["sub"], "user", ip,
        {"target_username": body.username, "was_locked": unlocked},
    )

    if not unlocked:
        return {"message": f"Account '{body.username}' was not locked"}
    return {"message": f"Account '{body.username}' has been unlocked"}


@router.post(
    "/logout-all",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(auth_general_rate_limit)],
)
async def logout_all_sessions(
    request: Request,
    current_user: dict = Depends(get_current_user),
    redis=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
):
    """Logout from all sessions and revoke all issued tokens."""
    ip = get_client_ip(request)
    user_id = current_user["sub"]
    iat = current_user.get("iat", 0)

    now = int(_time.time())

    # Revoke all tokens issued up to now
    await token_revocation_service.revoke_all_user_tokens(redis, user_id, now)

    # Revoke all Redis sessions
    count = await session_service.revoke_all_sessions(redis, user_id)

    await audit_service.log_event(
        db, "logout_all", user_id, "user", ip,
        {"username": current_user["username"], "sessions_revoked": count},
    )

    return {"message": f"All sessions revoked ({count} sessions)"}
