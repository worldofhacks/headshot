# T-F18a Test Agent report

Status: **DONE_WITH_CONCERNS**

## Provenance and dependency gate

- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F18a`
- Branch: `ticket/T-F18a-canonical-console-navigation`
- Reviewed planning base: `7838a5fc3d0e667913adc38785374e9cd8d1288c`
- Product-code baseline: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
- Test-review commit repaired: `c8fc2a6aaa06846aab4a7a390a12a70cc9b85df8`

The five commits from `1ac3ee0` through `7838a5f` change only plans, tickets, prompts, and plan-review
reports. Product and pre-existing test files are byte-identical across that range. The earlier
report incorrectly called `7838a5f` an implementation base; it is the reviewed **planning** base
named by the dispatch.

The ticket's later freeze prerequisite is not yet satisfiable: no local or remote ref currently
contains integrated T-F16f, T-F17f, and T-F19e commits. Only T-F16a and T-F17a RED branches exist.
This repaired suite is therefore provisional and must be transplanted onto the eventual recorded
dependency-integration SHA, with baseline and RED rerun, before it can freeze or be given to an
Implementation Agent. No integration SHA is fabricated here.

Changed scope remains limited to:

- `console/tests/router.test.ts`
- `console/tests/contracts.test.ts`
- `console/tests/browser/console.spec.ts`
- this report

No product source, plan, ticket, deployment, live target, or external service was changed.

## Review repairs

1. Removed the independent desktop landmark-name and mobile `aria-current` RED. T-F18l retains the
   full route/accessibility matrix. T-F18a now checks only destination labels/order, exact
   cardinality, retired-label absence, and activation to `/coverage`.
2. Added bare, query-only, hash-only, and combined `/resilience` tables. Every case requires one
   `replaceState`, zero `pushState`, unchanged history length, stripped search/hash, Coverage
   rendering, and no second replacement on `popstate`.
3. Replaced self-generated codec checks with independently authored encoded bookmarks, exact
   route-builder outputs, and App-level assertions that Live, Findings, and Approval entity
   identities reach the selected screen unchanged without URL rewriting.
4. Added a runtime contract that rejects programmatic construction of a `resilience` route; the
   compatibility path is inbound-only.
5. Completed the invalid-route matrix for every collection-only screen and malformed entities on
   all three entity-capable screens.
6. Changed the E2E compatibility case to direct `page.goto("/resilience?...#...")` navigation and
   executed all affected cases against Vite's deterministic localhost browser-test mode.

## Baseline

Before T-F18a tests, the reviewed planning base was green:

```text
cd console
npm test -- --run tests/router.test.ts tests/contracts.test.ts
PASS: 2 files, 18 tests

npm test
PASS: 12 files, 75 tests
```

After the review repairs, all ten unaffected unit/component files remain green:

```text
npm test -- --run tests/adversarial-text.test.tsx tests/analytics.test.tsx \
  tests/api-client.test.ts tests/birdseye.test.tsx tests/command-button.test.tsx \
  tests/console-events.test.tsx tests/observability.test.ts \
  tests/production-policy.test.ts tests/read-models.test.tsx tests/stream.test.ts
PASS: 10 files, 57 tests
```

## Intentional deterministic RED

```text
cd console
npm test -- --run tests/router.test.ts tests/contracts.test.ts --reporter=dot
RED as intended: 2 files failed; 30 tests failed and 35 passed
```

All failures are assertions against absent T-F18a behavior, with no import, transform, fixture,
collection, or setup errors:

| Criterion | RED failures | Missing behavior proved |
|---|---:|---|
| AC-1 | 3 | Desktop/mobile still expose separate `Coverage` and `Resilience` destinations, so the canonical label cannot be found or activated. |
| AC-2 | 7 | Bare/query/hash/combined compatibility URLs are not replaced, parsing still returns the Resilience screen, and programmatic construction remains possible. |
| AC-3 | 15 | Invalid URLs are rendered under misleading locations; malformed Findings/Approval identities are accepted as null; every unsupported-screen URL lacks replacement normalization. |
| AC-4 | 5 | Dot-segment identities can be emitted or accepted as entity routes. Fixed encoded bookmark, exact encoder, same-origin, and App propagation cases remain passing controls. |

## Intentional local-browser RED

```text
cd console
npm run test:browser -- --grep 'T-F18a'
RED as intended: 3 failed
```

- AC-1 reached the rendered local console and failed because the desktop canonical destination
  count was `0`, expected `1`.
- AC-2 directly loaded the compatibility URL and failed because it remained
  `/resilience?window=30d#latest-regression`, expected canonical `/coverage`.
- AC-3 reached the Live fallback and failed because the URL remained
  `/unknown?next=/findings#fragment`, expected canonical `/live`.

There were no server-start, authentication-fixture, selector-setup, browser-launch, or collection
errors. Playwright used `vite --mode browser-test` on `127.0.0.1:4174`; that mode aliases Clerk to
checked-in fixtures and serves same-origin API fixtures. No live target or external service was
accessed.

## Static and safety checks

```text
cd console
npm run typecheck
PASS

npm run check:forbidden
PASS

git diff --check
PASS
```

There is no console lint script in `console/package.json` or its CI job. Vitest and Playwright both
loaded/transformed the changed TypeScript successfully. Repository Ruff is Python-only and remains
baseline-red on unrelated pre-existing files; no Python file is in this diff.

Final safety checks:

```text
git diff --check
PASS

bash scripts/secret_scan.sh
PASS: secret scan clean (931 files)

gitleaks dir . --redact --no-banner --exit-code 1
PASS: no leaks found
```

Resilience/regression data and its API remain untouched. T-F18c still owns the merged Coverage &
Regression page contents.
