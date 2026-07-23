# Migration note: 0010 Regression replay

`0010` is an additive expansion after `0009`.

- Adds append-only replay plans, replay results, and versioned regression cases.
- Replay plans remain blocked pending separate human authorization and cannot dispatch target traffic.
- Replay results must reference a persisted campaign run and its exact authorization scope hash.
- Regression-case admission requires a persisted disposition and deterministic replay result.
- Web can create blocked plans and admitted versions; only Runner can record execution results.

Compatibility: older Web and Runner builds ignore the new tables. Roll back application code while
retaining the expanded schema; database downgrade is reserved for local migration verification.
