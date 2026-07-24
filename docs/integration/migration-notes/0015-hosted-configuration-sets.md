# Migration note: 0015 hosted configuration sets

Revision `0015` is an additive expansion after `0014`.

- Adds append-only `hosted_configuration_sets`.
- Stores one Organization-scoped, content-addressed configuration payload and rationale with the
  actor's immutable user/session attribution.
- Requires lowercase 64-hex configuration and release hashes, an object-shaped JSON payload, and one
  configuration per Organization/release hash.
- Web may insert reviewed sets; Web and Runner may read them. Red Team, Recorder, Judge, Scheduler,
  and PUBLIC receive no table authority.
- An append-only trigger rejects update/delete.

The row is configuration evidence, not permission to run. A live hosted campaign must separately bind
the configuration-set hash, generation-policy hash, provider caps, target/corpus scope, nonce,
synthetic assertion, and human authorization.

## Compatibility and rollback

Older services ignore the new table. Code rollback should retain it because rows are immutable audit
artifacts and do not affect legacy execution. Database downgrade drops those artifacts and is
local-only once a row has been staged.
