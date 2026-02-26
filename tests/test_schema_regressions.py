import sys
from pathlib import Path

from sqlalchemy import Integer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from models.sensor import Sensor


def test_health_check_failures_column_is_integer():
    column = Sensor.__table__.columns["health_check_failures"]
    assert isinstance(column.type, Integer)
    assert column.default is not None
    assert column.default.arg == 0


def test_health_check_failures_migration_exists():
    versions_dir = Path(__file__).resolve().parent.parent / "app" / "alembic" / "versions"
    migration_files = list(versions_dir.glob("*20260216_0002*"))
    assert migration_files
