# T-F18a Test Design Re-review

Verdict: **CHANGES_REQUIRED**

Reviewed repair commit: `f0b0a1450ac9be72be81be6ea4aa67a9212ce107`

The repaired tests are not frozen. The prior accessibility RED, compatibility suffix/direct-route
gap, self-generated bookmark check, unexecuted browser RED, and incomplete invalid-screen matrix are
closed. Independent execution reproduced the claimed assertion-only RED. Two executable
test-design gaps remain, and the missing dependency-integration SHA independently prohibits formal
freeze or Implementation Agent dispatch.

## Findings

### Important — AC-1 still freezes CSS structure and an unspecified global order

The component tests locate navigation through `.sidebar nav` and `.mobile-nav`, then require every
unrelated destination to appear in one exact order
(`console/tests/contracts.test.ts:93-114,124-182`). The Playwright case repeats the CSS selectors
(`console/tests/browser/console.spec.ts:21-39`). T-F18a AC-1 requires exactly one
`Coverage & Regression` destination targeting `/coverage` and no `Resilience` destination; it does
not require these CSS classes or freeze the order of Live, Findings, Approvals, Agents, Tooling,
Traces, Costs, Targets, and Configuration. A semantically valid navigation refactor can therefore
fail these tests without violating the ticket. This does not fully close the prior finding to avoid
freezing a button role/order as the only valid implementation.

Required change: scope through existing navigation semantics without requiring a new accessibility
feature (for example, the first navigation landmark for desktop and the already-named mobile
landmark), and assert only exact Coverage cardinality, Resilience absence, and activation to
`/coverage`. Do not use CSS classes or global label order as the contract.

### Important — AC-4 still allows conditional open-redirect and traversal bugs

The new fixed bookmark and route-builder vectors correctly cover Unicode plus ordinary reserved
characters (`console/tests/router.test.ts:49-74`; `console/tests/contracts.test.ts:247-268`), but none
uses an authority-shaped identity such as `//external.example/...`, a scheme-shaped identity, or a
traversal-prefix identity such as `../config`. The negative cases reject only the exact identities
`.` and `..` (`console/tests/router.test.ts:85-98`). A lazy implementation can special-case a leading
`//`, `https://`, or `../` by returning it unencoded while passing every current positive and
negative assertion, violating AC-4's explicit no-open-redirect/no-path-traversal requirement.

Required change: add independently authored route-builder and parser vectors for authority-shaped,
scheme-shaped, and traversal-prefix opaque identities. Assert exact percent-encoded output,
same-origin URL resolution, canonical screen-path containment, and unchanged decoded identity.

### Blocking prerequisite — no dependency-integration SHA exists

The repaired report now states the provenance accurately
(`.tdd-swarm/reports/T-F18a-test.md:5-22`). No local or remote ref reviewed here contains integrated
T-F16f, T-F17f, and T-F19e commits, and no matching completion commit was found. The ticket forbids
RED before that integration point (`tickets/T-F18a.md:5-6,24-27`), while the execution plan makes the
single rebase a mechanical gate (`docs/planning/console-pages-remediation.md:156-159`).

No SHA may be invented. Even after the two test-design findings above are repaired, this suite may
only remain a provisional candidate. It cannot be formally frozen or handed to an Implementation
Agent. Once the real integration SHA exists, transplant/rebase the candidate tests onto it and
rerun the parent baseline, deterministic RED, affected Playwright RED, typecheck, and independent
test review. Only a PASS on that exact base freezes the tests.

## Closed findings and independent evidence

- Accessibility-only RED was removed; T-F18l retains the full accessibility matrix.
- Bare, query-only, hash-only, and combined `/resilience` cases require one replacement, no push,
  stripped suffixes, stable history length, Coverage rendering, and no repeat replacement
  (`console/tests/contracts.test.ts:186-211`).
- The Playwright compatibility case now directly navigates to `/resilience` and checks back/forward
  behavior (`console/tests/browser/console.spec.ts:42-53`).
- Every collection-only screen and malformed entity-capable screen is covered by deterministic
  invalid-route normalization (`console/tests/router.test.ts:26-47`;
  `console/tests/contracts.test.ts:213-245`).
- Fixed bookmarks, exact route-builder output, App identity propagation, and inbound-only
  Resilience construction are now covered; the hostile-prefix extension above remains required.
- Independent Vitest result: `2` files failed, `30` tests failed and `35` passed, matching the
  report; failures were assertion-only and attributable to missing T-F18a behavior.
- Independent local Playwright result: all `3` T-F18a tests failed at the intended AC-1, AC-2, and
  AC-3 assertions, with no launch, fixture, collection, or setup error.
- `npm run typecheck` and `git diff --check f0b0a145^ f0b0a145` passed.
- The reviewed repair changes only the three declared console test files and the Test Agent report.
  No product, deployment, live target, or external service was changed.

Coverage/regression data deletion and resilience-over-time contents remain correctly outside this
ticket. The retained Coverage screen is still exercised, while T-F18c owns the merged
resilience/regression projection and page heading.
