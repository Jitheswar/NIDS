import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from services.infisical_service import _resolve_environment


def test_resolve_environment_from_settings():
    with patch("services.infisical_service.settings.environment", "production"):
        assert _resolve_environment(None) == "prod"

    with patch("services.infisical_service.settings.environment", "staging"):
        assert _resolve_environment(None) == "staging"

    with patch("services.infisical_service.settings.environment", "development"):
        assert _resolve_environment(None) == "dev"


def test_resolve_environment_explicit_override():
    assert _resolve_environment("custom") == "custom"
