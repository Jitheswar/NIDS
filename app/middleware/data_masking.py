import re

# Fields that contain PII — values will be masked for non-admin roles
PII_FIELDS = {"ip_address", "source_ip", "dest_ip", "hostname", "username", "email"}

# Fields containing raw payload data — hidden entirely for non-admin roles
PAYLOAD_FIELDS = {"raw_payload", "packet_data", "captured_payload"}

SENSOR_METADATA_FIELDS = {
    "id",
    "sensor_id",
    "sensor_name",
    "name",
    "status",
    "network_segment",
    "activated_at",
    "created_at",
    "updated_at",
    "cert_serial",
    "cert_issued_at",
    "cert_expires_at",
    "health_check_failures",
    "serial",
    "expires_at",
}

MASK_CHAR = "*"


def mask_value(value: str) -> str:
    """Mask a string value, preserving first and last 2 characters if long enough."""
    if not value or len(value) <= 4:
        return MASK_CHAR * max(len(value), 4)
    return value[:2] + MASK_CHAR * (len(value) - 4) + value[-2:]


def mask_ip(ip: str) -> str:
    """Mask an IP address, preserving the first octet."""
    if not ip:
        return "***"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.*.*.*"
    # IPv6 — show first group only
    groups = ip.split(":")
    if len(groups) > 1:
        return f"{groups[0]}:****:****:****"
    return mask_value(ip)


def apply_data_masking(data: dict | list, user_roles: list[str]) -> dict | list:
    """Apply data masking based on the user's roles.

    Rules:
    - super_admin: full access to all fields
    - security_analyst: PII fields masked, raw payloads replaced with "[REDACTED]"
    - auditor: PII fields masked, raw payloads removed entirely
    - sensor_manager: only sensor metadata visible
    """
    if "super_admin" in user_roles:
        return data

    if isinstance(data, list):
        return [apply_data_masking(item, user_roles) for item in data]

    if not isinstance(data, dict):
        return data

    if "sensor_manager" in user_roles:
        return _filter_sensor_metadata(data)

    masked = {}
    for key, value in data.items():
        if key in PAYLOAD_FIELDS:
            if "auditor" in user_roles:
                continue  # Remove entirely for auditors
            elif "security_analyst" in user_roles:
                masked[key] = "[REDACTED]"
            else:
                continue  # Other roles don't see payloads
        elif key in PII_FIELDS:
            if isinstance(value, str) and _is_ip(value):
                masked[key] = mask_ip(value)
            elif isinstance(value, str):
                masked[key] = mask_value(value)
            else:
                masked[key] = value
        elif isinstance(value, dict):
            masked[key] = apply_data_masking(value, user_roles)
        elif isinstance(value, list):
            masked[key] = apply_data_masking(value, user_roles)
        else:
            masked[key] = value

    return masked


def _filter_sensor_metadata(data: dict | list) -> dict | list:
    if isinstance(data, list):
        return [_filter_sensor_metadata(item) for item in data]
    if not isinstance(data, dict):
        return data

    filtered = {}
    for key, value in data.items():
        if key not in SENSOR_METADATA_FIELDS:
            continue
        if isinstance(value, dict):
            filtered[key] = _filter_sensor_metadata(value)
        elif isinstance(value, list):
            filtered[key] = _filter_sensor_metadata(value)
        else:
            filtered[key] = value
    return filtered


def _is_ip(value: str) -> bool:
    """Check if a string looks like an IP address."""
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(ipv4_pattern, value)) or ":" in value
