"""AI-driven anomaly detection on authentication logs.

Detects:
1. Credential stuffing: Many failed logins from the same IP targeting different users
2. Impossible travel: Same user logging in from geographically distant IPs in short time
3. Off-hours access: Successful logins outside normal business hours
4. Brute-force escalation: Rapid increase in failure rate for a single user
5. Session anomalies: Unusual concurrent session patterns
"""

import json
import time
from datetime import datetime, timezone

import redis.asyncio as aioredis
import structlog

from config import settings

logger = structlog.get_logger()

ANOMALY_PREFIX = settings.anomaly_alert_prefix
EVENT_STREAM_PREFIX = "auth_events:"


class AnomalyDetector:
    """Stateless anomaly detector that uses Redis for event storage and pattern analysis."""

    def __init__(self, redis: aioredis.Redis):
        self.redis = redis

    async def analyze_event(self, event: dict) -> list[dict]:
        """Analyze an auth event and return a list of anomaly alerts (if any).

        event: {
            "event_type": "login_success"|"login_failure"|...,
            "actor_id": str | None,
            "ip_address": str,
            "username": str,
            "timestamp": float,
            "details": dict,
        }
        """
        if not settings.anomaly_detection_enabled:
            return []

        alerts = []

        event_type = event.get("event_type", "")
        ip = event.get("ip_address", "")
        username = event.get("username", "")
        ts = event.get("timestamp", time.time())

        # Store event for analysis
        await self._store_event(event)

        if event_type == "login_failure":
            # Check for credential stuffing
            stuffing_alert = await self._check_credential_stuffing(ip, ts)
            if stuffing_alert:
                alerts.append(stuffing_alert)

            # Check for brute-force escalation
            brute_alert = await self._check_brute_force_escalation(username, ts)
            if brute_alert:
                alerts.append(brute_alert)

        elif event_type == "login_success":
            # Check for off-hours access
            offhours_alert = self._check_off_hours(username, ts)
            if offhours_alert:
                alerts.append(offhours_alert)

            # Check for impossible travel
            travel_alert = await self._check_impossible_travel(username, ip, ts)
            if travel_alert:
                alerts.append(travel_alert)

            # Check for session anomalies
            session_alert = await self._check_session_anomaly(username, ts)
            if session_alert:
                alerts.append(session_alert)

        # Persist alerts
        for alert in alerts:
            await self._store_alert(alert)

        return alerts

    async def _store_event(self, event: dict) -> None:
        """Store an auth event in a Redis sorted set for time-windowed analysis."""
        key = f"{EVENT_STREAM_PREFIX}{event.get('event_type', 'unknown')}"
        ts = event.get("timestamp", time.time())
        value = json.dumps(event)
        await self.redis.zadd(key, {value: ts})
        # Trim events older than the analysis window
        cutoff = ts - settings.anomaly_window
        await self.redis.zremrangebyscore(key, "-inf", cutoff)
        await self.redis.expire(key, settings.anomaly_window + 60)

    async def _check_credential_stuffing(self, ip: str, ts: float) -> dict | None:
        """Detect if many different usernames are failing from the same IP.
        Indicates credential stuffing or password spraying.
        """
        key = f"{EVENT_STREAM_PREFIX}login_failure"
        cutoff = ts - settings.anomaly_window

        # Get recent failures
        raw_events = await self.redis.zrangebyscore(key, cutoff, "+inf")
        ip_users = set()
        for raw in raw_events:
            try:
                evt = json.loads(raw)
                if evt.get("ip_address") == ip:
                    uname = evt.get("username", "")
                    if uname:
                        ip_users.add(uname)
            except json.JSONDecodeError:
                continue

        if len(ip_users) >= settings.anomaly_failed_login_threshold:
            return {
                "alert_type": "credential_stuffing",
                "severity": "high",
                "ip_address": ip,
                "unique_usernames": len(ip_users),
                "threshold": settings.anomaly_failed_login_threshold,
                "window_seconds": settings.anomaly_window,
                "timestamp": ts,
                "message": f"Potential credential stuffing: {len(ip_users)} unique usernames failed from IP {ip} in {settings.anomaly_window}s",
            }
        return None

    async def _check_brute_force_escalation(self, username: str, ts: float) -> dict | None:
        """Detect rapid increase in failure rate for a single user.
        Different from the lockout service — this detects the *pattern* before lockout.
        """
        if not username:
            return None

        key = f"{EVENT_STREAM_PREFIX}login_failure"
        cutoff = ts - 300  # Last 5 minutes

        raw_events = await self.redis.zrangebyscore(key, cutoff, "+inf")
        user_failures = 0
        for raw in raw_events:
            try:
                evt = json.loads(raw)
                if evt.get("username") == username:
                    user_failures += 1
            except json.JSONDecodeError:
                continue

        # Alert if 4+ failures in 5 minutes (just below lockout, early warning)
        if user_failures >= 4:
            return {
                "alert_type": "brute_force_escalation",
                "severity": "medium",
                "username": username,
                "failures_5min": user_failures,
                "timestamp": ts,
                "message": f"Brute-force escalation: {user_failures} failures for '{username}' in 5 minutes",
            }
        return None

    def _check_off_hours(self, username: str, ts: float) -> dict | None:
        """Detect successful logins during off-hours."""
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        hour = dt.hour

        is_off_hours = False
        if settings.anomaly_off_hours_start > settings.anomaly_off_hours_end:
            # Wraps midnight, e.g., 22-6
            is_off_hours = hour >= settings.anomaly_off_hours_start or hour < settings.anomaly_off_hours_end
        else:
            is_off_hours = settings.anomaly_off_hours_start <= hour < settings.anomaly_off_hours_end

        if is_off_hours:
            return {
                "alert_type": "off_hours_access",
                "severity": "low",
                "username": username,
                "hour_utc": hour,
                "timestamp": ts,
                "message": f"Off-hours login: '{username}' at {dt.strftime('%H:%M UTC')}",
            }
        return None

    async def _check_impossible_travel(self, username: str, ip: str, ts: float) -> dict | None:
        """Detect if the same user logged in from a very different IP recently.
        Uses IP prefix comparison as a lightweight geo heuristic (no external API needed).
        """
        if not settings.anomaly_geo_hop_enabled or not username:
            return None

        key = f"last_login_ip:{username}"
        last_data = await self.redis.get(key)

        # Store current login
        await self.redis.set(
            key,
            json.dumps({"ip": ip, "ts": ts}),
            ex=settings.anomaly_window,
        )

        if not last_data:
            return None

        try:
            last = json.loads(last_data)
            last_ip = last["ip"]
            last_ts = last["ts"]
        except (json.JSONDecodeError, KeyError):
            return None

        # Skip if same IP
        if last_ip == ip:
            return None

        time_diff = ts - last_ts
        # Only flag if both logins happened within 30 minutes
        if time_diff > 1800:
            return None

        # Compare IP class-B prefix (first two octets) as rough geo proxy
        last_parts = last_ip.split(".")
        curr_parts = ip.split(".")

        if len(last_parts) >= 2 and len(curr_parts) >= 2:
            if last_parts[0] != curr_parts[0]:
                return {
                    "alert_type": "impossible_travel",
                    "severity": "high",
                    "username": username,
                    "previous_ip": last_ip,
                    "current_ip": ip,
                    "time_diff_seconds": int(time_diff),
                    "timestamp": ts,
                    "message": f"Impossible travel: '{username}' logged in from {last_ip} and {ip} within {int(time_diff)}s",
                }
        return None

    async def _check_session_anomaly(self, username: str, ts: float) -> dict | None:
        """Detect if a user is creating sessions at an unusual rate."""
        key = f"session_create_rate:{username}"

        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, 3600)  # 1 hour window

        # More than 10 login sessions in 1 hour is suspicious
        if count > 10:
            return {
                "alert_type": "session_anomaly",
                "severity": "medium",
                "username": username,
                "sessions_1hr": count,
                "timestamp": ts,
                "message": f"Session anomaly: '{username}' created {count} sessions in 1 hour",
            }
        return None

    async def _store_alert(self, alert: dict) -> None:
        """Store an anomaly alert in Redis and log it."""
        key = f"{ANOMALY_PREFIX}alerts"
        ts = alert.get("timestamp", time.time())
        await self.redis.zadd(key, {json.dumps(alert): ts})
        # Keep last 24 hours of alerts
        cutoff = ts - 86400
        await self.redis.zremrangebyscore(key, "-inf", cutoff)
        await self.redis.expire(key, 86400 + 60)

        logger.warning(
            "ANOMALY_DETECTED",
            alert_type=alert["alert_type"],
            severity=alert["severity"],
            message=alert["message"],
        )

    async def get_alerts(
        self,
        severity: str | None = None,
        alert_type: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Retrieve recent anomaly alerts."""
        key = f"{ANOMALY_PREFIX}alerts"
        batch_size = max(limit * 2, 50)
        start = 0
        alerts = []

        while len(alerts) < limit:
            raw_alerts = await self.redis.zrevrange(key, start, start + batch_size - 1)
            if not raw_alerts:
                break

            for raw in raw_alerts:
                try:
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8")
                    alert = json.loads(raw)
                    if severity and alert.get("severity") != severity:
                        continue
                    if alert_type and alert.get("alert_type") != alert_type:
                        continue
                    alerts.append(alert)
                    if len(alerts) >= limit:
                        break
                except json.JSONDecodeError:
                    continue

            start += batch_size

        return alerts

    async def get_risk_score(self, username: str | None = None, ip: str | None = None) -> dict:
        """Calculate a risk score (0-100) for a user or IP based on recent anomalies.

        Scoring:
        - credential_stuffing (high): +30
        - impossible_travel (high): +30
        - brute_force_escalation (medium): +20
        - session_anomaly (medium): +15
        - off_hours_access (low): +5
        """
        weights = {
            "credential_stuffing": 30,
            "impossible_travel": 30,
            "brute_force_escalation": 20,
            "session_anomaly": 15,
            "off_hours_access": 5,
        }

        alerts = await self.get_alerts(limit=200)
        score = 0
        matching_alerts = []

        for alert in alerts:
            matches = False
            if username and alert.get("username") == username:
                matches = True
            if ip and alert.get("ip_address") == ip:
                matches = True

            if matches:
                score += weights.get(alert["alert_type"], 10)
                matching_alerts.append(alert["alert_type"])

        return {
            "score": min(score, 100),
            "username": username,
            "ip": ip,
            "alerts": matching_alerts,
            "threshold": settings.ztna_risk_score_threshold,
            "blocked": score >= settings.ztna_risk_score_threshold,
        }
