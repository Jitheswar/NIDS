import json
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.anomaly_service import AnomalyDetector


def _make_redis_mock():
    redis = AsyncMock()
    redis.zadd = AsyncMock()
    redis.zremrangebyscore = AsyncMock()
    redis.expire = AsyncMock()
    redis.zrangebyscore = AsyncMock(return_value=[])
    redis.zrevrange = AsyncMock(return_value=[])
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.incr = AsyncMock(return_value=1)
    redis.exists = AsyncMock(return_value=0)
    return redis


@pytest.mark.asyncio
async def test_no_anomalies_on_normal_login():
    redis = _make_redis_mock()
    detector = AnomalyDetector(redis)

    alerts = await detector.analyze_event({
        "event_type": "login_success",
        "actor_id": "user1",
        "ip_address": "10.0.0.1",
        "username": "admin",
        "timestamp": time.time(),
    })

    # Off-hours may trigger, but no credential stuffing or brute force
    alert_types = {a["alert_type"] for a in alerts}
    assert "credential_stuffing" not in alert_types
    assert "impossible_travel" not in alert_types
    assert "brute_force_escalation" not in alert_types


@pytest.mark.asyncio
async def test_credential_stuffing_detection():
    redis = _make_redis_mock()

    # Simulate 12 different users failing from same IP
    failures = []
    for i in range(12):
        failures.append(json.dumps({
            "event_type": "login_failure",
            "ip_address": "10.0.0.99",
            "username": f"user{i}",
            "timestamp": time.time(),
        }))
    redis.zrangebyscore = AsyncMock(return_value=failures)

    detector = AnomalyDetector(redis)
    alerts = await detector.analyze_event({
        "event_type": "login_failure",
        "actor_id": None,
        "ip_address": "10.0.0.99",
        "username": "user12",
        "timestamp": time.time(),
    })

    alert_types = {a["alert_type"] for a in alerts}
    assert "credential_stuffing" in alert_types


@pytest.mark.asyncio
async def test_brute_force_escalation_detection():
    redis = _make_redis_mock()

    # Simulate 4 failures for same user in 5 min
    failures = []
    for i in range(4):
        failures.append(json.dumps({
            "event_type": "login_failure",
            "ip_address": "10.0.0.1",
            "username": "target_user",
            "timestamp": time.time() - (i * 30),
        }))
    redis.zrangebyscore = AsyncMock(return_value=failures)

    detector = AnomalyDetector(redis)
    alerts = await detector.analyze_event({
        "event_type": "login_failure",
        "actor_id": None,
        "ip_address": "10.0.0.1",
        "username": "target_user",
        "timestamp": time.time(),
    })

    alert_types = {a["alert_type"] for a in alerts}
    assert "brute_force_escalation" in alert_types


@pytest.mark.asyncio
async def test_impossible_travel_detection():
    redis = _make_redis_mock()

    # Previous login from very different IP 5 minutes ago
    redis.get = AsyncMock(return_value=json.dumps({
        "ip": "203.0.113.1",  # Different first octet
        "ts": time.time() - 300,
    }))

    detector = AnomalyDetector(redis)
    alerts = await detector.analyze_event({
        "event_type": "login_success",
        "actor_id": "user1",
        "ip_address": "10.0.0.1",
        "username": "admin",
        "timestamp": time.time(),
    })

    alert_types = {a["alert_type"] for a in alerts}
    assert "impossible_travel" in alert_types


@pytest.mark.asyncio
async def test_no_impossible_travel_same_ip():
    redis = _make_redis_mock()

    redis.get = AsyncMock(return_value=json.dumps({
        "ip": "10.0.0.1",
        "ts": time.time() - 300,
    }))

    detector = AnomalyDetector(redis)
    alerts = await detector.analyze_event({
        "event_type": "login_success",
        "actor_id": "user1",
        "ip_address": "10.0.0.1",
        "username": "admin",
        "timestamp": time.time(),
    })

    alert_types = {a["alert_type"] for a in alerts}
    assert "impossible_travel" not in alert_types


@pytest.mark.asyncio
async def test_session_anomaly_detection():
    redis = _make_redis_mock()
    redis.incr = AsyncMock(return_value=11)  # 11 sessions in 1 hour

    detector = AnomalyDetector(redis)
    alerts = await detector.analyze_event({
        "event_type": "login_success",
        "actor_id": "user1",
        "ip_address": "10.0.0.1",
        "username": "admin",
        "timestamp": time.time(),
    })

    alert_types = {a["alert_type"] for a in alerts}
    assert "session_anomaly" in alert_types


@pytest.mark.asyncio
async def test_risk_score_calculation():
    redis = _make_redis_mock()

    # Simulate stored alerts
    stored_alerts = [
        json.dumps({"alert_type": "credential_stuffing", "severity": "high", "ip_address": "10.0.0.99", "timestamp": time.time()}),
        json.dumps({"alert_type": "impossible_travel", "severity": "high", "username": "admin", "timestamp": time.time()}),
    ]
    redis.zrevrange = AsyncMock(return_value=stored_alerts)

    detector = AnomalyDetector(redis)
    risk = await detector.get_risk_score(ip="10.0.0.99")

    assert risk["score"] >= 30  # At least credential_stuffing weight
    assert "credential_stuffing" in risk["alerts"]


@pytest.mark.asyncio
async def test_risk_score_blocks_high_risk():
    redis = _make_redis_mock()

    # Enough alerts to exceed threshold (70)
    stored_alerts = [
        json.dumps({"alert_type": "credential_stuffing", "severity": "high", "ip_address": "evil.ip", "timestamp": time.time()}),
        json.dumps({"alert_type": "impossible_travel", "severity": "high", "ip_address": "evil.ip", "timestamp": time.time()}),
        json.dumps({"alert_type": "brute_force_escalation", "severity": "medium", "ip_address": "evil.ip", "timestamp": time.time()}),
    ]
    redis.zrevrange = AsyncMock(return_value=stored_alerts)

    detector = AnomalyDetector(redis)
    risk = await detector.get_risk_score(ip="evil.ip")

    assert risk["score"] >= 70
    assert risk["blocked"] is True


@pytest.mark.asyncio
async def test_get_alerts_filtered_paginates_until_limit():
    redis = _make_redis_mock()
    detector = AnomalyDetector(redis)

    raw_alerts = []
    for idx in range(120):
        severity = "high" if idx in {10, 75, 95} else "low"
        raw_alerts.append(
            json.dumps(
                {
                    "alert_type": "credential_stuffing",
                    "severity": severity,
                    "timestamp": time.time() - idx,
                }
            )
        )

    async def zrevrange_side_effect(_key, start, end):
        return raw_alerts[start : end + 1]

    redis.zrevrange = AsyncMock(side_effect=zrevrange_side_effect)

    alerts = await detector.get_alerts(severity="high", limit=2)

    assert len(alerts) == 2
    assert all(alert["severity"] == "high" for alert in alerts)
    assert redis.zrevrange.await_count >= 2
