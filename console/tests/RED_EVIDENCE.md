# Frontend RED evidence

The focused frontend suite was run before the production boundary existed.

- Command: `npm test`
- Result: 6 test files failed; 2 executable policy tests failed.
- Five suites could not resolve the intentionally absent `api/client`, `api/stream`,
  `api/contracts`, `router`, and `AdversarialText` modules.
- The source-policy suite reported 33 fixture, timer, browser-authority, unsafe-sink, or
  persistent-storage violations, including the production `data.ts` import.

This file records only the initial failing state. Current results are produced by the test
command and must remain green in CI.

## v1 contract hardening RED

The later focused `read-models` / `console-events` run also began RED: both files failed.
The read-model decoder module did not exist, cursorless `unavailable` did not preserve its
typed reason, and the initial cursorless-snapshot regression harness did not stabilize ready.
