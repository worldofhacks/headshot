# T-F18a Test Design Final Blocker Re-review

Verdict: **DESIGN_PASS_PROVISIONAL_NOT_FROZEN**

Reviewed candidate: `a4bf66815c99ac82a51251ac690396c12b2fdf6f`

Implementation dispatch: **BLOCKED** pending a recorded dependency-integration SHA.

This re-review is intentionally limited to the two remaining findings from
`e563063e2f63a72e2f9c15f8a84792f81be854fa`. Both test-design blockers are closed.
The suite is not frozen because T-F18a's mandatory dependency base does not yet exist.

## Closed blockers

### CSS and navigation-order overconstraint — closed

The component tests now scope through navigation landmarks instead of `.sidebar` or `.mobile-nav`
CSS structure (`console/tests/contracts.test.ts:101-143`). They assert only the exact
`Coverage & Regression` cardinality, absence of `Resilience`, and activation to `/coverage`; the
unrelated global destination order is no longer frozen. The browser test uses the same existing
desktop/mobile navigation semantics and the same ticket-owned assertions
(`console/tests/browser/console.spec.ts:21-40`).

This is faithful to AC-1 without imposing a class-name, DOM-layout, or global-order implementation.

### Authority, scheme, and traversal-prefix identity cases — closed

The shared hostile-identity table now independently covers:

- authority-shaped `//external.example/records`;
- scheme-shaped `https://external.example/steal?next=/config`;
- traversal-prefix `../config`.

For every case, the tests require exact percent-encoded construction, same-origin resolution,
containment beneath the canonical screen path, exact resolved pathname, and unchanged parser
identity (`console/tests/router.test.ts:5-22,95-113`). These assertions reject the lazy conditional
open-redirect and traversal implementations identified in the prior review while preserving valid
opaque identities as AC-4 requires.

## Independent evidence

- `git diff --check e563063..a4bf668` passed.
- Focused Vitest RED reproduced the report exactly: `2` files failed, `30` tests failed, and `41`
  passed. Failures were assertions against absent T-F18a behavior, not setup, import, transform, or
  collection errors.
- Focused Playwright RED reproduced all `3` expected failures at the AC-1, AC-2, and AC-3
  assertions, with the local Vite server and browser fixtures starting successfully.
- The repair changes only the three declared console test files and the Test Agent report. No
  product source or test file was edited by this reviewer.

## Mandatory dependency gate

The Test Agent report records that no local or remote ref contains integrated T-F16f, T-F17f, and
T-F19e commits (`.tdd-swarm/reports/T-F18a-test.md:18-22`). T-F18a explicitly forbids RED before
that integration point (`tickets/T-F18a.md:23-27`), and the execution plan defines the exact rebase
as a mechanical base gate (`docs/planning/console-pages-remediation.md:156-159`).

No dependency SHA may be invented. Once the real integration commit exists, transplant/rebase this
candidate onto that exact SHA and rerun the parent baseline, deterministic RED, affected
Playwright RED, typecheck, and independent test review. Until a PASS on that exact base, these tests
remain provisional, are not frozen, and must not be handed to an Implementation Agent.
