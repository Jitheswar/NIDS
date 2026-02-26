import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


def test_no_verify_false_in_services():
    services_dir = Path(__file__).resolve().parent.parent / "app" / "services"
    offenders = []
    for path in services_dir.rglob("*.py"):
        if "verify=False" in path.read_text(encoding="utf-8"):
            offenders.append(str(path))

    assert offenders == []


def test_sops_utility_removed():
    sops_file = Path(__file__).resolve().parent.parent / "app" / "utils" / "sops.py"
    assert not sops_file.exists()


def test_alembic_upgrade_invoked_on_startup():
    main_file = Path(__file__).resolve().parent.parent / "app" / "main.py"
    content = main_file.read_text(encoding="utf-8")
    assert 'command.upgrade(alembic_cfg, "head")' in content
    assert 'app_dir / "alembic"' in content
