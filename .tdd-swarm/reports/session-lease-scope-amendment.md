# SMART session-lease scope amendment — repair round 3

**Status: REPAIRED_PENDING_INDEPENDENT_REVIEW**

This is a planning-only repair of Important findings I1–I4 in the frozen
`.tdd-swarm/reports/session-lease-scope-review.md`. The review remains unchanged. This repair wrote
only tickets, prompts, the ticket index, the final-submission manifest, and this amendment report.
It did not edit application source, tests, the tracked target catalog, secrets, Railway state, or
git state. Pre-existing shared-worktree source/test changes remain out of scope and untouched.

The planning catalog baseline is `efd5ce3`; later shared-worktree commits are outside this repair.
The tracked, secret-free target catalog at
`config/targets/clinical-copilot-20260724.json` parses and remains byte-unchanged from that head.
No credential/session value or locally extracted artifact content was copied into planning.

## Finding closure

| finding | closure | owner chain |
|---|---|---|
| I1 — no production acquisition for the signed controller observation | **REPAIRED** | T-F05l → T-F05h → T-F05m |
| I2 — one final snapshot could not prove ordered rotation history | **REPAIRED** | T-F05o → T-F05n → T-F05g |
| I3 — T-F05j combined too many concerns for one swarm ticket | **REPAIRED** | T-F05j → {T-F05k,T-F05l} → T-F05m |
| I4 — Runner rejection text conflicted with queue sanitation | **REPAIRED** | T-F05j → T-F05f |

## I1 — fixed authenticated observation acquisition

T-F05h is now projection/verification only. Its runtime producer accepts only T-F05l's
non-serializable, single-use receipt; a caller, job, CLI, or serialized artifact cannot construct
that receipt. The separate evidence-only path CLI cannot satisfy T-F05m or Runner dispatch.

T-F05l is the sole production `DeploymentControllerObservationSource`:

- fixed Linux `AF_UNIX` `SOCK_SEQPACKET` endpoint under `/run/agentforge/controller`;
- no caller-selected path, URL, host, port, file, fallback, retry, or stdin;
- no-follow endpoint/trust-root ownership and replacement checks;
- `SO_PEERCRED` UID/GID verification plus Ed25519 source authentication;
- a fresh 32-byte challenge per call, bounded single-frame response, five-second deadline;
- exact request-nonce binding, freshness, non-increasing-sequence, and replay rejection;
- no successful envelope, projection, or validator-result cache.

T-F05m owns only the closed runtime provider. Every invocation performs:

```text
T-F05l acquire
  → T-F05h project/verify deployment state
  → T-F05i project/verify a new read-only repeatable-read control state
  → T-F05e validate both against the pinned context and exact current claim
```

Source unavailability, stale/replayed data, a partial pair, or prior success fails the current
invocation closed. Actual controller/database access remains separately authorized and is
zero-action `BLOCKED` when unavailable.

## I2 — complete ordered rotation proof

T-F05o owns strict start and terminal `RunnerRotationControlState/v1` artifacts. The start
projection requires authenticated draining state and durable admission closure, then freezes the
complete predecessor campaign/job set and event/job high-watermarks in one read-only
repeatable-read transaction. The terminal projection re-queries the same identities and proves:

- identical complete membership and lineage;
- no later predecessor campaign/job above the frozen high-watermarks;
- every campaign durably completed or hard-aborted;
- every owned job terminal; and
- zero live lease.

T-F05n authenticates a signed controller activation receipt and owns strict
`RunnerActivationEvent/v1` plus `RunnerRotationEvidence/v1`. Its verifier binds separately supplied
artifacts in the exact order:

```text
start control
  → terminal control
  → pre-activation zero-generation deployment
  → signed activation event
  → post-activation exactly-one-generation deployment
```

The chain requires exact hashes, rotation/release/manifest/context/fixture/generation identities,
the same bounded predecessor set, distinct nonces, and
`draining < zero < activation < final` controller sequence. Cross-authority order comes from
explicit hash links, not assumed clock comparability.

T-F05g's exact CLI now takes start, terminal, zero, activation, and final artifacts separately and
reauthenticates the entire chain. One final snapshot, an opaque activation/no-overlap hash, a local
queue count, a process boolean, a caller-combined document, or a terminal hard-abort with live jobs
cannot prove zero overlap.

## I3 — bounded ticket split

The former oversized runtime-lifecycle concern is divided into independently testable half-day owners:

| ticket | wave | single concern | unique deterministic test |
|---|---:|---|---|
| T-F05j | 11 | mandatory settings, strict reference, immutable job/store/queue persistence, queue sanitation | `tests/test_smart_session_lease_reference_persistence.py` |
| T-F05k | 12 | fixed-path create-only install, no-follow load, startup/post-claim pin | `tests/test_smart_session_lease_context_loader.py` |
| T-F05l | 12 | fixed authenticated controller-observation acquisition | `tests/test_deployment_controller_observation_source.py` |
| T-F05m | 13 | non-cached per-call runtime provider composition | `tests/test_authenticated_runner_state_provider.py` |

T-F05k and T-F05l are disjoint and may run together only after T-F05j. T-F05m follows both.
T-F05f, rotation, preflight, campaign, replay, stress, evidence, and documentation consumers were
rewired to the exact landed prerequisites they consume. Each focus ticket has one unique test and
five capable-model Test → Test Review → Implement → Code Review → Security prompts with explicit
write/report boundaries, a three-attempt cap, four-status return contract, and no-network/no-main
rules.

## I4 — queue-compatible sanitized rejection

T-F05j freezes the existing lease-owned queue boundary rather than bypassing it. A nonretryable
SMART policy rejection has:

- public/persisted message exactly `worker-supplied failure detail omitted`;
- machine failure code exactly `smart_session_lease_rejected`;
- durable status exactly `dead_letter`;
- outcome exactly `FailureOutcome.DEAD_LETTERED`; and
- cleared lease fields with no retry.

Any queue-required internal detail is sanitized and never persisted, returned, logged, or exposed.
T-F05f may perform only the atomic claim before validation; on failure it invokes that landed
queue contract once. Every campaign/attempt/work-unit/evidence mutation, secret resolution,
adapter/client construction, network, and spend remains after successful J/K/M validation.

## Authorized target-catalog ownership

T-F05p is the sole target-catalog owner in wave 7. It freezes the exact two authorized staging
target identities, identical Web/Runner catalog bytes and hash, chat-only enablement, explicit
denial of unreviewed surfaces, opaque credential bindings, Runner-only resolution, and exactly one
target/session/patient selection per campaign. T-F05e, T-F05f, T-F05g, public preflight, and all
downstream evidence consumers depend on that contract.

The catalog contains no credential/session value. Web may read the non-secret catalog but cannot
receive or resolve credential variables. Runner uses a reviewed fixed resolver mapping and pins
one T-F05d patient/context identity with the selected target, surface, reference, and generation.

## Serialized graph

```text
{T-F05a,T-F05d} → T-F05h → T-F05i ─┐
T-F05p ──────────────────────────────┴→ T-F05e → T-F05j
                                                   ├→ T-F05k ─┐
                                                   └→ T-F05l ─┴→ T-F05m
                                                                  ├→ T-F05f ─┐
                                                                  └→ T-F05o ─┴→ T-F05n
                                                                                  ↓
                                                                               T-F05g
                                                                                  ↓
                                                                          {T-F05c,T-F06a}
```

All dependencies are strictly earlier-wave. Conservative exact/prefix/glob scope analysis found
48 overlapping ticket pairs; every pair is ancestor-serialized and none overlaps unordered in the
same wave.

## Verification

All checks were local and read-only after planning edits. No repository source/test suite was run.

| check | result |
|---|---|
| Frontmatter, filename/ID parity, focus required sections, sequential AC IDs | PASS |
| Unique IDs, dependency existence, acyclicity, strictly earlier dependencies | PASS — 46 tickets, waves 0–25 |
| `TICKETS.md` wave membership parity | PASS — 46/46 |
| File-scope overlap ancestry / same-wave collisions | PASS — 48/48 serialized; 0 same-wave |
| Focus deterministic test scopes | PASS — 13/13 unique |
| Focus capable-model five-role prompt sets | PASS — 65/65 |
| Operational prompt inventory and four-status/attempt contracts | PASS — 180 |
| Exact focus report paths plus no-network/no-main boundaries | PASS — 65/65 |
| Stale combined-state/provider contracts and invalid regex anchors outside frozen review | PASS — none |
| Python 3.12.9 ASCII fullmatch and Draft 2020-12 terminal-newline parity | PASS |
| Tracked target catalog JSON parse and unchanged-from-head check | PASS |
| Repository secret-pattern scan | PASS — 771 files |
| Planning trailing whitespace, CRLF, and tracked `git diff --check` | PASS |

Inventory is **46 tickets, 180 operational prompts, waves 0–25**.

The amendment is ready for a new independent, planning-only re-review. It is not implementation or
live-execution approval: deterministic tickets still require RED/review/freeze/GREEN/code/security
completion, and controller/database/activation/Railway/campaign/replay/stress activity still
requires its own exact authorization.
