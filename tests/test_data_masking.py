import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from middleware.data_masking import apply_data_masking, mask_ip, mask_value


def test_mask_value_short():
    assert mask_value("ab") == "****"


def test_mask_value_long():
    result = mask_value("admin@nids.local")
    assert result.startswith("ad")
    assert result.endswith("al")
    assert "*" in result


def test_mask_ip_v4():
    result = mask_ip("192.168.1.100")
    assert result == "192.*.*.*"


def test_mask_ip_v6():
    result = mask_ip("2001:db8::1")
    assert result.startswith("2001:")
    assert "****" in result


def test_super_admin_sees_all():
    data = {
        "ip_address": "192.168.1.1",
        "username": "admin",
        "raw_payload": "SENSITIVE DATA",
    }
    result = apply_data_masking(data, ["super_admin"])
    assert result["ip_address"] == "192.168.1.1"
    assert result["username"] == "admin"
    assert result["raw_payload"] == "SENSITIVE DATA"


def test_analyst_pii_masked():
    data = {
        "ip_address": "192.168.1.1",
        "username": "admin",
        "raw_payload": "SENSITIVE DATA",
        "event_type": "login",
    }
    result = apply_data_masking(data, ["security_analyst"])
    assert result["ip_address"] == "192.*.*.*"
    assert result["raw_payload"] == "[REDACTED]"
    assert result["event_type"] == "login"


def test_auditor_no_payload():
    data = {
        "ip_address": "10.0.0.5",
        "raw_payload": "SENSITIVE DATA",
        "event_type": "login",
    }
    result = apply_data_masking(data, ["auditor"])
    assert "raw_payload" not in result
    assert result["ip_address"] == "10.*.*.*"
    assert result["event_type"] == "login"


def test_nested_masking():
    data = {
        "event": "alert",
        "details": {
            "ip_address": "172.16.0.1",
            "hostname": "sensor-01.local",
        },
    }
    result = apply_data_masking(data, ["security_analyst"])
    assert result["details"]["ip_address"] == "172.*.*.*"
    assert "*" in result["details"]["hostname"]


def test_list_masking():
    data = [
        {"ip_address": "10.0.0.1", "event": "a"},
        {"ip_address": "10.0.0.2", "event": "b"},
    ]
    result = apply_data_masking(data, ["auditor"])
    assert result[0]["ip_address"] == "10.*.*.*"
    assert result[1]["ip_address"] == "10.*.*.*"


def test_sensor_manager_no_payload():
    data = {
        "sensor_id": "sensor-1",
        "status": "active",
        "ip_address": "10.0.0.1",
        "raw_payload": "SENSITIVE DATA",
        "event_type": "login",
        "details": {"hostname": "sensor-01.local"},
    }
    result = apply_data_masking(data, ["sensor_manager"])
    assert result["sensor_id"] == "sensor-1"
    assert result["status"] == "active"
    assert "raw_payload" not in result
    assert "ip_address" not in result
    assert "event_type" not in result
    assert "details" not in result
