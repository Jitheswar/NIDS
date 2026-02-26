import hashlib
import secrets


def generate_api_key(length: int = 32) -> str:
    """Generate a high-entropy API key with nids_ prefix.
    length: number of random bytes (32 = 256-bit).
    """
    raw = secrets.token_hex(length)
    return f"nids_{raw}"


def hash_api_key(raw_key: str) -> str:
    """Hash an API key using SHA-256. Returns hex digest."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
