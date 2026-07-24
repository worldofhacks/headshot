"""Make an observed provider model substitution recordable without trusting it.

``agent_execution_provider_identity`` asserted ``returned_model = model``, which made a provider
substitution physically unstorable: if OpenRouter served something other than the authorized model
the row could not be written at all, so the platform destroyed the only evidence that its own
"requested identity is not observed identity" claim depends on.

The all-or-nothing observation tuple is unchanged. What changes is that ``returned_model`` is now
treated as an observation rather than an authority claim, and is allowed to differ — but never on a
``succeeded`` row, so recording a substitution can never become trusting its output.

Revision ID: 0019
Revises: 0018
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OBSERVATION_TUPLE = (
    "((returned_model IS NULL AND upstream_provider IS NULL "
    "AND provider_request_id IS NULL) OR "
    "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
    "AND provider_request_id IS NOT NULL))"
)


def upgrade() -> None:
    op.drop_constraint("agent_execution_provider_identity", "agent_executions", type_="check")
    op.create_check_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        _OBSERVATION_TUPLE + " AND (returned_model IS NULL OR returned_model = model "
        "OR status <> 'succeeded')",
    )


def downgrade() -> None:
    # A row recording a substitution cannot satisfy the old constraint, so the observation has to
    # go. It must be cleared as a whole: agent_execution_hosted_measurement_tuple requires the
    # seven observation columns to be all-NULL or all-NOT-NULL, so nulling only the three identity
    # columns leaves a shape the older constraint rejects and aborts the rollback on exactly the
    # rows this migration exists to permit.
    #
    # The substitution stays provable after the rollback through the agent.failed audit event,
    # which records requested_model and returned_model together. (Not through
    # provider_call_events — that table has no production writer yet; wiring it is T-F17c.)
    # The cost goes with it. Left behind, a measured cost on a row whose usage columns are now
    # NULL projects as accounting_status='unavailable' carrying a measured value, which
    # AgentActivityReadModel rejects — and because agent activity serializes every row in one
    # response, a single rolled-back substitution would fail the whole view.
    op.execute(
        "UPDATE agent_executions SET "
        "returned_model = NULL, upstream_provider = NULL, provider_request_id = NULL, "
        "input_tokens = NULL, output_tokens = NULL, reasoning_tokens = NULL, "
        "physical_attempts = NULL, "
        "measured_cost = NULL, cost_measurement_state = 'not_observed' "
        "WHERE returned_model IS NOT NULL AND returned_model <> model"
    )
    op.drop_constraint("agent_execution_provider_identity", "agent_executions", type_="check")
    op.create_check_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        _OBSERVATION_TUPLE + " AND (returned_model IS NULL OR returned_model = model)",
    )
