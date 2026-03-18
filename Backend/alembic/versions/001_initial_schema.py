"""initial_schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-03-17

Creates: users, scan_history, login_history
Also fixes the legacy `scans` table by adding the missing `prediction` column.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── users ──────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",            sa.Integer(),     primary_key=True),
        sa.Column("username",      sa.String(50),    nullable=False),
        sa.Column("email",         sa.String(120),   nullable=False),
        sa.Column("password_hash", sa.String(256),   nullable=False),
        sa.Column("is_active",     sa.Boolean(),     server_default="1"),
        sa.Column("created_at",    sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.UniqueConstraint("email",    name="uq_users_email"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email",    "users", ["email"])

    # ── scan_history ───────────────────────────────────────────────────────────
    op.create_table(
        "scan_history",
        sa.Column("id",          sa.Integer(), primary_key=True),
        sa.Column("user_id",     sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url",         sa.Text(),    nullable=False),
        sa.Column("is_phishing", sa.Boolean(), nullable=False),
        sa.Column("prediction",  sa.String(20), nullable=False),
        sa.Column("confidence",  sa.Float(),   nullable=False),
        sa.Column("scanned_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_history_user_id", "scan_history", ["user_id"])

    # ── login_history ──────────────────────────────────────────────────────────
    op.create_table(
        "login_history",
        sa.Column("id",           sa.Integer(),    primary_key=True),
        sa.Column("user_id",      sa.Integer(),    sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address",   sa.String(45),   nullable=True),
        sa.Column("user_agent",   sa.String(256),  nullable=True),
        sa.Column("success",      sa.Boolean(),    server_default="1"),
        sa.Column("logged_in_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_login_history_user_id", "login_history", ["user_id"])

    # ── fix legacy `scans` table (adds missing `prediction` column) ─────────
    # Uses batch mode so SQLite can handle the ALTER TABLE
    with op.batch_alter_table("scans", schema=None) as batch_op:
        # Only add if the table exists but column is missing.
        # Alembic will skip gracefully if scans table doesn't exist.
        try:
            batch_op.add_column(sa.Column("prediction", sa.String(20), nullable=True))
        except Exception:
            pass


def downgrade() -> None:
    op.drop_table("login_history")
    op.drop_table("scan_history")
    op.drop_table("users")