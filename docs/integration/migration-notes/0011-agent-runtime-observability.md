# Migration note: 0011 Agent runtime observability

`0011` is an additive expansion after `0010`.

- Adds exactly four runtime role identifiers: Orchestrator, Red Team, Judge, and Documentation.
- Adds append-only agent configuration versions and a durable execution ledger.
- Agent executions may transition once from `running` to a terminal state so the console can show
  real in-progress activity, latency, hashes, lineage, errors, token observations, and measured cost.
- Adds security-tool source lineage to campaign attempts.
- Hosted Red Team and Documentation assignments remain staged; they cannot alter an already
  authorized corpus or replace the deterministic Judge.

Compatibility: older services ignore the new tables and nullable lineage columns. Roll back
application code while retaining the expanded schema; database downgrade is local-only.
