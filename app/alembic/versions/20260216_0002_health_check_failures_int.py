"""Convert sensors.health_check_failures from string to integer.

Revision ID: 20260216_0002
Revises: 20260216_0001
Create Date: 2026-02-16 16:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260216_0002"
down_revision: Union[str, None] = "20260216_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "sensors" not in inspector.get_table_names():
        return
    columns = {col["name"]: col for col in inspector.get_columns("sensors")}
    if "health_check_failures" not in columns:
        return

    dialect = bind.dialect.name
    if dialect == "mysql":
        bind.execute(
            sa.text(
                """
                UPDATE sensors
                SET health_check_failures = '0'
                WHERE health_check_failures IS NULL
                   OR health_check_failures NOT REGEXP '^[0-9]+$'
                """
            )
        )
        bind.execute(
            sa.text(
                "ALTER TABLE sensors MODIFY COLUMN health_check_failures INT NOT NULL DEFAULT 0"
            )
        )
        return

    with op.batch_alter_table("sensors") as batch_op:
        batch_op.alter_column(
            "health_check_failures",
            existing_type=sa.String(length=11),
            type_=sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "mysql":
        bind.execute(
            sa.text(
                "ALTER TABLE sensors MODIFY COLUMN health_check_failures VARCHAR(11) NOT NULL DEFAULT '0'"
            )
        )
        return

    with op.batch_alter_table("sensors") as batch_op:
        batch_op.alter_column(
            "health_check_failures",
            existing_type=sa.Integer(),
            type_=sa.String(length=11),
            nullable=False,
            server_default=sa.text("'0'"),
        )
