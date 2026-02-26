"""Initial schema with audit chain state.

Revision ID: 20260216_0001
Revises:
Create Date: 2026-02-16 15:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260216_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "sensors" not in tables:
        op.create_table(
            "sensors",
            sa.Column("id", sa.CHAR(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("network_segment", sa.String(length=100), nullable=False),
            sa.Column(
                "status",
                sa.Enum("pending", "active", "disabled", name="sensor_status"),
                nullable=False,
                server_default="pending",
            ),
            sa.Column("activated_at", sa.DateTime(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("created_by", sa.String(length=255), nullable=False),
            sa.Column("cert_serial", sa.String(length=128), nullable=True),
            sa.Column("cert_expires_at", sa.DateTime(), nullable=True),
            sa.Column("cert_issued_at", sa.DateTime(), nullable=True),
            sa.Column(
                "health_check_failures",
                sa.String(length=11),
                nullable=False,
                server_default="0",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )
        op.create_index("ix_sensors_name", "sensors", ["name"], unique=False)
        op.create_index("ix_sensors_cert_serial", "sensors", ["cert_serial"], unique=False)

    if "api_keys" not in tables:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.CHAR(length=36), nullable=False),
            sa.Column("sensor_id", sa.CHAR(length=36), nullable=False),
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column(
                "used",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("created_by", sa.String(length=255), nullable=False),
            sa.ForeignKeyConstraint(["sensor_id"], ["sensors.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_api_keys_sensor_id", "api_keys", ["sensor_id"], unique=False)
        op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=False)

    if "audit_logs" not in tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column(
                "timestamp",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("event_type", sa.String(length=50), nullable=False),
            sa.Column("actor_id", sa.String(length=255), nullable=True),
            sa.Column(
                "actor_type",
                sa.Enum("user", "sensor", "system", name="actor_type"),
                nullable=False,
            ),
            sa.Column("ip_address", sa.String(length=45), nullable=False),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
        op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"], unique=False)

    if "audit_chain_state" not in tables:
        op.create_table(
            "audit_chain_state",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("previous_hash", sa.String(length=64), nullable=False),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        bind.execute(
            sa.text(
                "INSERT INTO audit_chain_state (id, previous_hash) VALUES (:id, :previous_hash)"
            ),
            {"id": 1, "previous_hash": "0" * 64},
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "audit_chain_state" in tables:
        op.drop_table("audit_chain_state")
    if "audit_logs" in tables:
        op.drop_table("audit_logs")
    if "api_keys" in tables:
        op.drop_table("api_keys")
    if "sensors" in tables:
        op.drop_table("sensors")
