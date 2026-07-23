"""Authorize the private scheduler's regression-planning and heartbeat tables.

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-23
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "GRANT SELECT ON TABLE target_definitions, target_lifecycle_events, "
        "regression_case_versions, regression_dispositions, vuln_reports, "
        "regression_replay_plans, runtime_component_status TO headshot_scheduler"
    )
    op.execute(
        "GRANT INSERT ON TABLE regression_replay_plans TO headshot_scheduler"
    )
    op.execute(
        "GRANT INSERT, UPDATE ON TABLE runtime_component_status TO headshot_scheduler"
    )


def downgrade() -> None:
    op.execute(
        "REVOKE INSERT, UPDATE ON TABLE runtime_component_status FROM headshot_scheduler"
    )
    op.execute(
        "REVOKE INSERT ON TABLE regression_replay_plans FROM headshot_scheduler"
    )
    op.execute(
        "REVOKE SELECT ON TABLE target_definitions, target_lifecycle_events, "
        "regression_case_versions, regression_dispositions, vuln_reports, "
        "regression_replay_plans, runtime_component_status FROM headshot_scheduler"
    )
