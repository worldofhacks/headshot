# T-F18a Test Design Review

Verdict: **CHANGES_REQUIRED**

Reviewed RED commit: `98d3c40922419206af6eb06afd9089f264a513c8`

The tests are not frozen. AC tags are present and the deterministic unit/component RED is real, but
the suite was created from the wrong dependency base, includes RED unrelated to this ticket, and
still permits lazy compatibility and encoding implementations.

## Findings

### Critical — RED was created before the ticket's mechanical dependency gate

The Test Agent records base `7838a5fc3d0e667913adc38785374e9cd8d1288c`
(`.tdd-swarm/reports/T-F18a-test.md:5-9`). That is the console planning branch, not an integration
commit containing T-F16f, T-F17f, and T-F19e. The ticket expressly says RED begins only after those
three dependencies are integrated (`tickets/T-F18a.md:5-6,24-27`), and the execution plan calls this
a mechanical rebase gate (`docs/planning/console-pages-remediation.md:156-159`).

Required change: recreate/rebase the test-only commit on the recorded integration SHA containing all
three prerequisites, then rerun the parent baseline and every RED check. Do not freeze results from
this base.

### Important — two accessibility requirements cause RED outside T-F18a

The desktop accessible-name test (`console/tests/contracts.test.ts:128-134`) fails solely because the
current label is on the complementary landmark rather than the nested navigation landmark. The
mobile `aria-current` requirement (`console/tests/contracts.test.ts:182-195`) will remain RED after
the ticket's label/route change. The Playwright test also requires the new desktop name
(`console/tests/browser/console.spec.ts:23-24`). None is required by T-F18a AC-1; the deterministic
route/accessibility manifest and full landmark/current-state matrix belong to T-F18l
(`tickets/T-F18l.md:31-50`). These failures therefore do not prove missing T-F18a behavior.

Required change: remove those independent accessibility assertions from T-F18a or formally move the
requirements into this ticket before RED. Keep behavior-level checks that desktop/mobile expose
exactly one `Coverage & Regression` destination, no `Resilience` destination, and that activation
targets `/coverage`. Avoid freezing the current button role/order as the only valid implementation.

### Important — the E2E compatibility case is not the required direct route and “any query/hash” is under-tested

The browser case starts at `/live`, writes history with `pushState`, and synthesizes `popstate`
(`console/tests/browser/console.spec.ts:50-55`); it never directly navigates to `/resilience`, despite
the ticket's explicit direct-route E2E plan (`tickets/T-F18a.md:41-44`). The component test covers
only one exact combined suffix (`console/tests/contracts.test.ts:199-218`). An implementation
special-cased to that suffix can pass while query-only, hash-only, empty, or differently encoded
suffixes violate AC-2.

Required change: use a small deterministic table for bare, query-only, hash-only, and combined
`/resilience` URLs, asserting canonical `/coverage`, stripped search/hash, one replacement, no push,
unchanged history length, and Coverage rendering. Make at least one Playwright case a real
`page.goto("/resilience...")` navigation and retain the back/forward no-loop proof.

### Important — AC-4 round-trip is self-generated and does not preserve existing encoded links

The AC-4 positive cases generate a path with `routePath` and immediately parse that same path
(`console/tests/router.test.ts:37-50`). A coordinated codec change can therefore pass while breaking
existing percent-encoded Live, Findings, or Approval bookmarks. The prior direct encoded contract
was removed. The suite also never proves that the public route builder can no longer emit the
retired `resilience` screen, so a lazy implementation may leave `ScreenName`, `routePath`, and the
orphan App switch branch intact while only special-casing inbound parsing.

Required change: add fixed, independently authored encoded pathname vectors and exact route-builder
outputs for all three entity-capable screens, including Unicode and reserved characters. Add a
compile-time or runtime contract preventing programmatic construction of a Resilience route. The
temporary compatibility path must be inbound-only and render Coverage.

### Important — browser RED evidence is missing

All three new Playwright tests were authored but explicitly not executed
(`.tdd-swarm/reports/T-F18a-test.md:53-55`). TDD-swarm requires every new test to fail for the missing
feature rather than for fixture, selector, or setup defects. Static typecheck cannot establish that
the local browser fixture reaches the assertions.

Required change: after rebasing, execute the affected Playwright cases against the deterministic
local browser-test fixture, with no live target or external traffic, and record exact right-reason
RED output before freeze.

### Minor — AC-3 permits per-screen special-casing

The unsupported-entity vectors cover only Coverage and Agents
(`console/tests/router.test.ts:26-35`; `console/tests/contracts.test.ts:220-243`). A lazy
screen-specific implementation can pass while Tooling, Traces, Costs, Targets, or Configuration
still accept a misleading entity URL. Malformed entity decoding is similarly exercised only on
Findings.

Required change: table-drive every collection-only canonical screen and all three entity-capable
screens for the relevant unsupported-entity/malformed-escape families. One browser representative
per family is sufficient once the complete router contract exists.

## Independent checks

- Parent baseline at `7838a5f`: `2` files, `18` tests passed.
- Reviewed RED: `2` files failed, `19` tests failed and `23` passed. Failures are assertions, but the
  accessibility failures above are not caused by T-F18a.
- Unaffected console suite slice: `10` files, `57` tests passed.
- `git diff --check 98d3c40^ 98d3c40`: passed.
- No Playwright, live browser, live target, deployment, or external network action was performed in
  this review.

Coverage/regression data deletion and resilience-over-time page contents are correctly absent from
this test diff: the retained Coverage screen remains covered, while T-F18c owns the merged
resilience/regression projection and heading.
