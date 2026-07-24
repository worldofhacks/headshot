# Migration note: 0016 agent and Langfuse delivery state

Revision `0016` follows `0015` and changes observability delivery semantics.

- Replaces the request-unique `outbound_http_requests.trace_id` constraint with a non-unique index so
  one campaign trace may contain multiple physical request observations.
- Adds `langfuse_verified_at` and a check requiring every `exported` outbound request to have an exact
  verification timestamp.
- Reclassifies historical `exported` request rows as `queued`, because a non-raising SDK flush did not
  prove remote visibility.
- Adds `langfuse_status`, `langfuse_verified_at`, checks, and a delivery index to
  `agent_executions`.
- Allows only `not_attempted`, `disabled`, `queued`, `exported`, or `error`; `exported` always requires
  an exact query-back timestamp.

PostgreSQL remains authoritative. This migration does not backfill historical agent observations or
manufacture remote Langfuse records.

## Compatibility and rollback

An older reader can ignore the added columns, but older code may assume one trace ID per outbound
request. Before code rollback, quiesce new work and confirm the prior image does not rely on that
uniqueness.

The database downgrade rewrites every request trace ID to `md5(request_id)` before recreating the
unique constraint. That operation intentionally loses shared campaign-trace identity and should not
be used as routine production rollback. Retain the expanded schema and roll application code back to
a known-compatible image instead.
