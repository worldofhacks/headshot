# T-F18a Test Agent report

Status: **DONE**

- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-T-F18a`
- Branch: `ticket/T-F18a-canonical-console-navigation`
- Base: `7838a5fc3d0e667913adc38785374e9cd8d1288c`
- Scope changed: `console/tests/router.test.ts`, `console/tests/contracts.test.ts`,
  `console/tests/browser/console.spec.ts`, and this report only.
- Production source, network, deployment, live target, and browser execution: untouched.

## Baseline

Before adding T-F18a tests:

```text
cd console
npm test -- --run tests/router.test.ts tests/contracts.test.ts
PASS: 2 files, 18 tests

npm test
PASS: 12 files, 75 tests
```

After adding T-F18a tests, the ten unaffected unit/component files remain green:

```text
npm test -- --run tests/adversarial-text.test.tsx tests/analytics.test.tsx \
  tests/api-client.test.ts tests/birdseye.test.tsx tests/command-button.test.tsx \
  tests/console-events.test.tsx tests/observability.test.ts \
  tests/production-policy.test.ts tests/read-models.test.tsx tests/stream.test.ts
PASS: 10 files, 57 tests
```

## Intentional RED

```text
cd console
npm test -- --run tests/router.test.ts tests/contracts.test.ts --reporter=dot
RED as intended: 2 files failed; 19 tests failed and 23 passed
```

All failures are assertions against missing T-F18a behavior, not import, transform, fixture, or
setup errors:

| Criterion | RED failures | Missing behavior proved |
|---|---:|---|
| AC-1 | 5 | Desktop/mobile still expose `Coverage` plus `Resilience`, the desktop route list lacks an accessible navigation name, and the canonical mobile current-route state cannot be reached. |
| AC-2 | 3 | `/resilience` still parses/renders as its own screen and neither query/hash nor history entry is replace-normalized to `/coverage`. |
| AC-3 | 6 | Invalid URLs, including a prefixed `/resilience/extra`, render a fallback without replacing the misleading URL; malformed entity decoding is also accepted as Findings with a null identity. |
| AC-4 | 5 | Dot-segment entity IDs are emitted/accepted even though browsers interpret them as path traversal. Valid Unicode, slash, query, fragment, and authority-shaped identities already round-trip on the same origin and remain passing controls. |

The Playwright additions independently cover desktop/mobile navigation, the compatibility
redirect's back/forward behavior, and each invalid-route family. They were authored but not run
because this Test Agent was explicitly prohibited from browser access.

## Static and safety checks

```text
cd console
npm run typecheck
PASS

npm run check:forbidden
PASS

git diff --check
PASS

bash scripts/secret_scan.sh
PASS: secret scan clean (930 files)

gitleaks dir . --redact --no-banner --exit-code 1
PASS: no leaks found
```

There is no console lint script in `console/package.json` or the console CI job. The repository
Python lint commands were still checked and fail on the unchanged base: `ruff check .` reports 116
pre-existing Python findings, and `ruff format --check .` reports 19 pre-existing Python files.
None is in this ticket's TypeScript/Markdown diff.

The suite is intentionally left RED for the independent test-design review and subsequent
Implementation Agent. Resilience/regression data and its API were not deleted or changed; T-F18c
retains ownership of the merged Coverage & Regression page contents.
