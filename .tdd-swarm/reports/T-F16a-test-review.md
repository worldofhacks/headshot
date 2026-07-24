# T-F16a Test Review — Attempt 2

Status: `BLOCKED(TEST_CHANGES_REQUIRED)`

Freeze verdict: `NOT FROZEN`

Review attempt: `2/3`

Re-review commit: `6d77eb6fb93c4aa720831bdca179e89d9326a921`

## Provenance

- Product baseline: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
- RED commit: `e437a8c1749320d9466b29fa937882036c2c4afc`
- The scoped product files are byte-identical between the baseline and RED commit.
- Reviewed the ticket, canonical PRD, locked adapter plan, test-review prompt, complete test
  module, and Test Agent report.

## Findings

No Critical findings.

### Important 1 — The integration fixture omits Week 1 and authorizes document surfaces at the wrong version

`tests/test_final_target_surface_policy.py:358-400` defines only the five Week 2 surfaces and
`tests/test_final_target_surface_policy.py:570-595` exercises only that catalog. The ticket's test
plan requires the catalog-to-registry-to-canonical-scope contract for all final surfaces, including
the Week 1 UI route `/app`. In addition, every fixture surface is enabled at target/surface version
`2.0.0`, including lab and intake, contrary to the locked staged contract: `2.0.0` enables
chat/evidence/UI while document surfaces remain disabled; document-capable activation is a
separately hashed `2.1.0` state.

Required change: add Week 1 chat/UI/evidence coverage (including `/app` with query field `sid`) and
exercise catalog -> registry -> scope for both targets. Represent the locked `2.0.0` disabled
document state and the separate `2.1.0` document-capable state instead of treating enabled document
surfaces as `2.0.0`.

### Important 2 — Evidence authentication and exact document-upload field omission are not hostile-tested

`tests/test_final_target_surface_policy.py:677-731` mutates only evidence operation placement/field
and then asserts one valid no-auth scope. It never submits a self-consistent rehashed evidence policy
whose `auth_mode`, `explicit_no_auth`, and `credential_ref` attempt to inherit the target session.
The placement table also omits a hostile document-upload case with a missing or wrong exact field
name.

Required change: add isolated evidence-policy mutations for each auth-triad field and the combined
authenticated-evidence downgrade, proving rejection before credential resolution. Add document
upload mutations with `credential_field_name=None` and a wrong field such as `sid`, while retaining
the existing UI `session_id` attack.

### Important 3 — Fixture incompleteness and duplicate-ref coverage can be bypassed

`tests/test_final_target_surface_policy.py:748-832` removes only `workflow_id`, exercises only the
lab descriptor, and duplicates the identical descriptor inside one policy. An implementation that
special-cases that field and permits other incomplete descriptors or the same `opaque_ref` on two
surfaces would pass. Relative/traversal filesystem locators are also not exercised.

Required change: parameterize omission of every required descriptor field, cover both document
surface shapes, reject relative/traversal locators, and add a catalog-level conflicting/cross-surface
duplicate `opaque_ref` case.

### Important 4 — AC-4's nonfinite/unbounded/exact maxima contract is not covered

`tests/test_final_target_surface_policy.py:859-887` applies nonfinite and `"unbounded"` values only
to `retry_count`; maxima are tested only as the understated integers `33` and `66`. A parser that
accepts boolean, nonfinite, string-unbounded, negative, or overstated operation/logical/physical
maxima can pass. The suite also permits an incorrect global `retry_count <= 1` rule because it has
no valid non-document policy with a retry count above one.

Required change: add invalid operation-level and top-level logical/physical maxima covering boolean,
negative, nonfinite, string-unbounded, understated, and overstated values. Add a valid
non-document/generic operation with retry count `2` and exact retry-inclusive arithmetic, while
retaining zero upload retries and the one-retry document poll/read ceiling.

### Important 5 — AC-5 side-effect ordering and independent drift facts are not proven

`tests/test_final_target_surface_policy.py:910-927` instruments only the adapter factory.
The `credential` and `fixture` counters are incremented inside that same factory, so they are not
independent observations of secret or fixture resolution. At
`tests/test_final_target_surface_policy.py:930-948`, target-auth and path fallback are changed in one
payload, allowing rejection of either field to mask acceptance of the other.

Required change: instrument independent adapter, credential, and fixture resolution boundaries (or
otherwise observe those actual boundaries) and prove all remain untouched on policy drift. Split
target-auth and path fallback into independent cases, and parameterize self-consistent rehashed
drift for method/path, adapter profile, retry, fixture, and credential facts so each required
registry comparison is independently observable.

### Important 6 — AC-6 compatibility/fallback and migration assertions are too weak

`tests/test_final_target_surface_policy.py:548-560` builds a mixed legacy fixture with several
simultaneous shape changes, and `tests/test_final_target_surface_policy.py:951-966` accepts any
`TargetCatalogError`; this does not isolate rejection of the `54b3a4d` target-wide
`payload_profiles` fallback. The test covers legacy chat but not the required synthetic definition.
Finally, `tests/test_final_target_surface_policy.py:970-981` is satisfiable by disconnected keywords
and does not prove that old approvals cannot authorize the v2 hash.

Required change: add a synthetic-catalog compatibility case; make the target-wide
`payload_profiles` fixture otherwise valid with a control case and assert the ambiguity-specific
refusal; and strengthen migration coverage to bind exact old/new versions, changed hash inputs,
old-approval invalidation, staged activation order, and rollback semantics rather than bare
substring presence.

## Verification evidence

- Focused RED:
  `/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/bin/python -m pytest tests/test_final_target_surface_policy.py -q --tb=no`
  -> exit `1`; `50` failed, `0` passed, `0` collection/setup errors.
- Failure-causality rerun with line tracebacks -> all failures are missing v2 surface-policy
  behavior, acceptance of the partial target-wide fallback, or the absent migration note.
- Scoped baseline:
  `python -m pytest tests/target/test_relative_path_parameters.py tests/target/test_target_spec.py -q`
  -> exit `0`; `79` passed.
- Ruff check and format check -> exit `0`.
- Repository secret scan -> exit `0`.
- Static test inspection found no socket, HTTP client, subprocess, fixture-byte read, credential
  read, or target call.
- Required wrapper:
  `.tdd-swarm/run-local-gates.sh tickets/T-F16a.md 1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
  -> exit `127`; the wrapper is absent at this dependency base.

The RED failures have correct feature-missing causality, but the Important coverage defects above
must be closed and independently re-reviewed before the test contract can be frozen.

## Attempt 2 re-review

The repair closes Important findings 1, 2, and 6. It adds the requested Week 1 and staged-version
chains, evidence auth/field attacks, synthetic/legacy controls, old-scope rejection, and stronger
migration assertions. Findings 3, 4, and 5 are materially improved but are not yet clean enough to
freeze.

### Remaining Important 1 — The cross-surface duplicate test is RED for an error-message mismatch

`tests/test_final_target_surface_policy.py:1125-1141` expects a duplicate/fixture-specific message
from `TrustedTargetCatalog.from_environment`. Against the locked product baseline, the catalog
already raises `TargetCatalogError`; the test fails only because the existing generic message does
not match the regex. Error-message specificity is not part of AC-3, and this failure does not prove
the missing duplicate-ref behavior.

Required change: first load an otherwise-identical valid v2.1 control through the shared canonical
catalog helper, then submit the duplicate-ref mutation and assert typed fail-closed rejection.
Do not require human-readable error text unless a typed diagnostic code is added to the contract.

### Remaining Important 2 — Intake's second state-changing upload can still receive retries

`tests/test_final_target_surface_policy.py:1185-1212` hostile-tests only the five lab operations.
The intake `duplicate_check` operation is a second multipart `POST /documents`, but no negative case
sets its retry count above zero. A lazy implementation can special-case the lab `upload` operation,
allow retries for intake `duplicate_check`, and pass all 101 tests.

Required change: parameterize the document retry-ceiling test by surface and operation, including
both intake operations with a self-consistently rederived physical maximum.

### Remaining Important 3 — Valid early definition rejection is treated as a test failure

`tests/test_final_target_surface_policy.py:1320-1389` sends method, path, and adapter-profile drift
through `_parse_canonical_surface`, whose helper calls `pytest.fail` on `DefinitionError`. AC-5
allows any drift to fail before secret/fixture/adapter side effects; a correct implementation may
reject a profile-invalid method, path, or adapter profile while constructing the definition. The
test instead requires those hostile policies to be accepted before registry rejection.

Required change: treat `DefinitionError` as a valid early fail-closed outcome with zero side effects.
For facts that remain structurally valid, continue through registry resolution and assert the three
independent probes remain untouched.

## Attempt 2 verification

- Focused RED -> exit `1`; `101` failed, `0` passed, `0` collection/setup errors.
- Representative causality sample confirmed missing v2 behavior, accepted target-wide fallback,
  and absent migration note. The cross-surface duplicate case alone failed on the unrequired regex.
- Scoped baseline -> exit `0`; `79` passed.
- Ruff check/format, secret scan, and diff check -> exit `0`.
- Scoped product files remain byte-identical to `1ac3ee0`.
- No network/client/credential/fixture access was introduced.
- Required wrapper remains unavailable at this dependency base and exits `127`.

Freeze remains blocked until the three Important test-design defects above are repaired.
