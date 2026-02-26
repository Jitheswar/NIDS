import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from utils.crypto import generate_api_key, hash_api_key


def test_generate_api_key_prefix():
    """API key should start with nids_ prefix."""
    key = generate_api_key()
    assert key.startswith("nids_")


def test_generate_api_key_length():
    """API key should have correct hex length after prefix."""
    key = generate_api_key(32)
    raw = key.removeprefix("nids_")
    assert len(raw) == 64  # 32 bytes = 64 hex chars


def test_generate_api_key_unique():
    """Two generated keys should be different."""
    key1 = generate_api_key()
    key2 = generate_api_key()
    assert key1 != key2


def test_hash_api_key_deterministic():
    """Hashing the same key should produce the same hash."""
    key = "nids_abc123"
    h1 = hash_api_key(key)
    h2 = hash_api_key(key)
    assert h1 == h2


def test_hash_api_key_length():
    """SHA-256 hash should be 64 hex chars."""
    key = "nids_test"
    h = hash_api_key(key)
    assert len(h) == 64


def test_hash_api_key_different_inputs():
    """Different keys should produce different hashes."""
    h1 = hash_api_key("nids_key1")
    h2 = hash_api_key("nids_key2")
    assert h1 != h2


def test_sensor_create_schema_valid():
    """Valid sensor create schema should pass."""
    from schemas.sensor import SensorCreate

    sensor = SensorCreate(name="test-sensor-01", network_segment="172.28.0.0/16")
    assert sensor.name == "test-sensor-01"
    assert sensor.network_segment == "172.28.0.0/16"


def test_sensor_create_schema_invalid_name():
    """Sensor name with special chars should fail validation."""
    from schemas.sensor import SensorCreate

    with pytest.raises(Exception):
        SensorCreate(name="test sensor!!", network_segment="172.28.0.0/16")


def test_sensor_create_schema_invalid_cidr():
    """Invalid CIDR should fail validation."""
    from schemas.sensor import SensorCreate

    with pytest.raises(Exception):
        SensorCreate(name="test-sensor", network_segment="not-a-cidr")


def test_sensor_create_schema_invalid_cidr_range():
    """Out-of-range CIDR should fail validation."""
    from schemas.sensor import SensorCreate

    with pytest.raises(Exception):
        SensorCreate(name="test-sensor", network_segment="999.999.999.999/99")


def test_sensor_create_schema_canonicalizes_cidr():
    """Host CIDR should be canonicalized to network CIDR."""
    from schemas.sensor import SensorCreate

    sensor = SensorCreate(name="test-sensor", network_segment="192.168.1.42/24")
    assert sensor.network_segment == "192.168.1.0/24"


def test_sensor_cert_issue_request_valid():
    from schemas.sensor import SensorCertIssueRequest

    body = SensorCertIssueRequest(csr_pem="-----BEGIN CERTIFICATE REQUEST-----\n...\n")
    assert body.csr_pem.startswith("-----BEGIN")


def test_sensor_cert_response_has_no_private_key_field():
    from schemas.sensor import SensorCertResponse

    response = SensorCertResponse(
        sensor_id="sensor-1",
        cert_pem="-----BEGIN CERTIFICATE-----\n...\n",
        ca_pem="-----BEGIN CERTIFICATE-----\n...\n",
        expires_at="2026-02-17T00:00:00Z",
        serial="01AB",
    )

    assert "key_pem" not in response.model_dump()
