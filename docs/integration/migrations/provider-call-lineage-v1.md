# Provider-call lineage v1 migration

Revision `0016` is an additive PostgreSQL migration over `0015`. It adds immutable
`provider_call_invocations` and append-only `provider_call_events`, plus canonical nullable cost
state and physical source-event references on `agent_executions`.

The upgrade does not infer provider observations from configured assignments. Historical logical
costs equal to the old default zero are reclassified as `not_observed` with SQL `NULL`; positive
historical costs remain `measured`. New physical facts require a committed invocation, exact
organization/execution/attempt ownership, and one terminal event per invocation. Final intent is
stored on the event and cannot change on replay. A partial unique index permits only one final event
per logical execution.

Success persistence requires the provider-confirmed returned model and upstream to match the
precommitted request, complete usage fields, and measured cost. The logical success output hash
content-addresses the canonical, sanitized terminal-event contract; raw provider content is never
persisted. Organization-filtered reads are repository primitives and require the caller to supply a
scope already authorized at the API boundary.

Only `headshot_runner` may insert lineage rows. `headshot_runner` and `headshot_web` may read them;
no application role may update, delete, or truncate either table.

Downgrade drops the two additive relations and lineage columns, restores unknown logical costs to
the `0015` numeric-zero representation, and restores the prior logical terminal-shape constraint. A
v1 terminal failure has no provider-output hash, so downgrade translates its sanitized final-event
contract into the content hash required by the `0015` terminal shape before dropping lineage.
That rollback necessarily loses v1-only physical lineage; it does not change any logical identity,
status, timing, trace, or detail field that predates `0016`.
