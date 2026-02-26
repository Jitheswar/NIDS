from pathlib import Path

import yaml


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_compose(path: str) -> dict:
    compose_file = _repo_root() / path
    with compose_file.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _to_text(value) -> str:
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value or "")


def test_default_compose_keycloak_not_dev_mode():
    compose = _load_compose("docker-compose.yml")
    command = _to_text(compose["services"]["keycloak"]["command"])
    assert "start-dev" not in command
    assert command.startswith("start ")


def test_default_compose_redis_healthcheck_uses_redisciliauth():
    compose = _load_compose("docker-compose.yml")
    healthcheck = _to_text(compose["services"]["redis"]["healthcheck"]["test"])
    assert "-a" not in healthcheck
    assert "REDISCLI_AUTH" in healthcheck


def test_dev_compose_intentionally_uses_start_dev():
    compose = _load_compose("docker-compose.dev.yml")
    command = _to_text(compose["services"]["keycloak"]["command"])
    assert "start-dev" in command


def test_dev_compose_uses_dev_app_image():
    compose = _load_compose("docker-compose.dev.yml")
    dockerfile = compose["services"]["app"]["build"]["dockerfile"]
    assert dockerfile == "Dockerfile.dev"
