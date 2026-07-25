# Final-submission execution manifest (session-lease scope repair round 3)

> **Historical planning artifact — not the final release manifest.** Current release facts and
> pending bindable fields live in `SUBMISSION.md` and
> `docs/submission-artifacts/RELEASE_BINDING.md`. Nothing here overrides retained manifests.

[locked-decision] Canonical requirements remain `Week_3_AgentForge.pdf`; this is not a replacement PRD/roadmap.

## Evidence boundary

- Baseline `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, GitHub CI green and the
  exact commit mirrored to GitLab. GitLab pipeline status is not a release gate.
- Planning catalog baseline `efd5ce3` adds only the tracked secret-free target catalog; this repair does not amend it. Later shared-worktree commits are not attributed to this planning repair.
- Legacy summary `aceddc495808427992efbd2b73b3598d` claims 9 HTTP 200 / 9 evidence /
  9 `INDETERMINATE`. Its `$0.09` figure has no retained billing or immutable request-cost manifest
  and is quarantined: actual spend is unavailable, not `$0.09`.
- Judge baseline 60% agreement/33.3% false negatives/60% abstention is failed.
- [locked-decision] None proves calibrated safe/unsafe outcomes, findings, current-SHA live trace, production isolation, performance, or report completeness.

## Closure ownership

| requirement family | owner(s) |
|---|---|
| mechanical swarm gates | T-F00 |
| sanitized export / final reconciliation | T-F01a / T-F01b |
| package-authority root contracts | T-F02 |
| Judge code / authorized calibration evidence | T-F03a / T-F03b |
| Red Team controls / authorized provider eval | T-F04a / T-F04b |
| hosted role configuration/preflight/transport/smoke | T-F04c through T-F04h |
| durable release lineage | T-F05a |
| authorized target/session/patient evidence | T-F05d |
| tracked non-secret Clinical Co-Pilot target catalog and Web/Runner parity | T-F05p |
| signed deployment observation projection | T-F05h |
| current authenticated control-state projection | T-F05i |
| immutable SMART context and sole fresh validator | T-F05e |
| configuration/reference/job persistence and sanitized queue failure contract | T-F05j |
| fixed-path secure context install/load/pin | T-F05k |
| fixed authenticated controller-observation acquisition | T-F05l |
| non-cached per-call runtime state provider | T-F05m |
| exact bounded predecessor campaign/job history | T-F05o |
| signed activation event and five-stage rotation evidence | T-F05n |
| Runner post-claim/per-attempt enforcement | T-F05f |
| zero-overlap config and full-chain verifier/runbooks | T-F05g |
| campaign/replay/performance/evidence/docs consumers | T-F05c, T-F05b, T-F06a through T-F15 |

## Invariants

- No production/config code without reviewed failing deterministic tests; sampled behavior uses graded eval artifacts.
- No controller/database/activation/network/spend/live traffic without exact named authorization; absent authority is zero-action `BLOCKED`.
- T-F04h remains target-free smoke. T-F05d remains the synthetic patient fixture authority.
- T-F05p's tracked secret-free catalog contains exactly `clinical-copilot-week1` and `clinical-copilot-week2`. Staging Web and Runner load identical file bytes/hash. Only chat surfaces are enabled; UI, evidence/search, and upload/write surfaces remain explicitly disabled until their own adapter RED/GREEN/code/security reviews land.
- Every live campaign selects exactly one T-F05p target, one enabled session-auth chat surface, one opaque credential reference/generation, and one T-F05d patient/context identity. T-F05e/T-F05f pin the entire target/session/patient tuple; no switching or cross-target resolution exists.
- Web can read the non-secret catalog but never receives or resolves target credential variables. Runner alone holds sealed variables mapped by reviewed opaque credential bindings. No credential/session value or locally extracted browser/bundle artifact enters source control, tickets, prompts, reports, tests, logs, jobs, or evidence.
- T-F05h verifies strict signed `DeploymentControllerObservation/v1` envelopes including request nonce, controller sequence, truthful phase, and rotation hash fields. T-F05l is the only production acquisition channel: one fixed no-follow Unix seqpacket endpoint, peer plus Ed25519 authentication, fresh challenge, bounded response, freshness/replay checks, no cache/retry/fallback.
- T-F05i projects current control state in one authenticated read-only repeatable-read transaction. T-F05m performs T-F05l acquire → T-F05h project → T-F05i project → T-F05e validate on every call; it never uses H's offline path CLI, caller artifacts, combined state, or prior success.
- T-F05j owns only settings/reference/job persistence and preserves the queue sanitizer. T-F05k owns only fixed-path install/load/pin. These land before T-F05m and T-F05f.
- The only public/persisted SMART policy-rejection message is `worker-supplied failure detail omitted`. Separate machine state is `smart_session_lease_rejected`, durable `dead_letter`, and `DEAD_LETTERED`. Any queue-required internal failure detail is sanitized and is never exposed or persisted.
- T-F05o freezes the exact complete predecessor campaign/job set plus high-watermarks after durable admissions closure, then proves the identical set terminal with no later predecessor work and zero live leases.
- T-F05n authenticates a signed controller activation receipt and binds exactly start control → terminal control → zero-generation deployment → activation event → exactly-one-generation final deployment. Hash links establish cross-authority order; signed controller sequence/nonces/times reject replay. A final snapshot or opaque activation hash alone proves nothing.
- T-F05g consumes and reauthenticates every separate chain artifact. No caller-combined document, local queue count, process boolean, overwrite, reload, rolling overlap, or in-place session/patient swap is authority.
- T-F05f permits only atomic queue claim before immediate J/K/M validation. All other mutation, resolution, adapter/client construction, network, and spend follow success. Every physical attempt obtains a new L→H/I refresh through M.
- T-F05e timestamp/reference languages remain Python 3.12 ASCII `re.fullmatch` plus portable Draft 2020-12 patterns, exact lengths, semantic validation, and explicit control rejection including terminal CR/LF.
- No PHI/secrets/sessions/raw hostile evidence in artifacts; staging/test is never called production. Swarm never merges main, publishes critical findings, remediates, load-tests, or posts socially autonomously.

## Deterministic order

```text
{T-F05a,T-F05d} -> T-F05h -> T-F05i --\
T-F05p --------------------------------> T-F05e -> T-F05j
                                                   /          \
                                              T-F05k          T-F05l
                                                   \          /
                                                     T-F05m
                                                     /     \
                                                T-F05f     T-F05o
                                                     \     /
                                                     T-F05n
                                                        |
                                                     T-F05g
                                                        |
                                                {T-F05c,T-F06a}
```

T-F05p also precedes every target/session consumer. Every campaign/replay/stress/docs ticket directly
depends on each artifact it consumes. External authority may block observation/evidence but never
justify skipping or parallelizing this deterministic chain.

## Deadline triage

- **P0 deterministic:** existing hosted/smoke order; A+D+P → H → I → E → J → K+L → M → F+O → N → G → C/06a. Tests use only synthetic signatures, fake read-only transactions, fake IPC/stat/resolver, and zero network.
- **P1 external:** actual controller IPC/database projection/activation receipt and T-F03b/T-F04b/T-F04e/T-F05b/T-F06b/T-F07b may remain `BLOCKED`; no caller-created state/catalog/session substitutes.
- **P2 packaging:** T-F12/T-F13 and every live/release/cost claim consume all landed contract/test/review hashes or remain incomplete.

## Open owner gates

- [open-question] Supply immutable `campaign.json` selecting one catalog target, one enabled chat surface, one session generation, and one complete T-F05d patient identity with exact allowlist/corpus/config/smoke/reviews/caps/principals.
- [open-question] Supply deployment/controller and control-projector trust roots, workload DB identity, immutable context reference, and maximum lifetime; none is inferred/defaulted.
- [open-question] Authorize controller IPC, private database projection, activation action/receipt, campaign, replay, and stress separately. Absence is zero-action `BLOCKED`.
- [open-question] Provision only Runner-side sealed variables matching reviewed opaque bindings. Never copy values or discovered local artifacts into planning/evidence.
- [open-question] Retain distinct Evidence/Security reviewers, launcher/Approver, Judge, Red Team, replay, stress, reproduction, drill, publication, Railway/Clerk, and deployment authorities.

[locked-decision] P0 deterministic proof is prioritized; P1/P2 remain honestly blocked when authority or evidence is absent.
