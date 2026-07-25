# SMART session-lease scope re-review — round 3

**Verdict: REVIEW_CHANGES_REQUIRED**

**Findings: Critical 0 · Important 4 · Minor 0**

This was an independent, plan-only, zero-network review of the frozen repair-round-2 amendment.
No source, test, ticket, prompt, configuration, Railway state, credential, controller/database
observation, deployment, provider/target call, spend, or git state was changed. The only write was
this required review report. The chat-disclosed session value was not used, repeated, passed to a
command, hashed, stored, or accepted as an artifact input.

## Findings

### I1 — The fresh-state provider has no owned way to acquire T-F05h's required signed controller observation

- **Evidence:** T-F05h's producer accepts a signed
  `DeploymentControllerObservation/v1` as its only source input, and its public command receives that
  observation by path (`tickets/T-F05h.md:36,40`). Actual controller observation/querying is
  expressly outside T-F05h (`tickets/T-F05h.md:31-32,54-56`). T-F05j nevertheless requires
  `AuthenticatedRunnerStateProvider.observe(context, now, current_claim)` to invoke that producer on
  every call, but the closed provider has no signed-observation parameter, fixed source reference,
  controller client/IPC interface, mounted-file contract, or acquisition authority
  (`tickets/T-F05j.md:33-40`). T-F05j also excludes live source observation and network from its
  scope (`tickets/T-F05j.md:53-55`).
- **Impact:** The signature prevents a caller from forging controller facts, but the deployed Runner
  still cannot obtain the fresh signed envelope needed for immediate post-claim and per-attempt
  checks. An implementer must invent a source channel or the production provider always fails
  closed. This leaves the end-to-end producer/delivery lifecycle incomplete despite the new
  authenticated artifact.
- **Exact repair:** Freeze one production `DeploymentControllerObservationSource` before T-F05j's
  provider integration. Specify its fixed trusted transport or no-follow local IPC/mount location,
  envelope size/ownership/replacement rules, freshness/nonce/replay behavior, source authentication,
  authorization boundary, and stable failures. The provider must acquire a new signed envelope
  through that closed source on every call and pass it to T-F05h; no caller/job/CLI-selected source,
  stale file, or cached success may substitute. Keep deterministic tests synthetic and networkless,
  and keep actual controller access separately authorized/`BLOCKED` when unavailable.

### I2 — T-F05g's one-snapshot CLI cannot mechanically prove its required rotation history

- **Evidence:** The exact verifier command accepts only one deployment artifact and one control
  artifact and exits 0 only for the final exactly-one-generation state
  (`tickets/T-F05g.md:32`). AC-3 and all five T-F05g prompts require proof of an ordered sequence:
  admissions stopped, drained-or-terminal prior campaigns, authenticated zero active generations
  with all predecessors stopped, activation, then authenticated exactly one new generation
  (`tickets/T-F05g.md:33`; `.tdd-swarm/prompts/T-F05g-test.md:2`). There is no sequence/evidence
  manifest, phase argument, previous/zero/final artifact input, or hash chain. T-F05h carries only an
  `activation/no-overlap evidence SHA-256`, with no owned schema or verifier for the referenced
  evidence (`tickets/T-F05h.md:36`). T-F05i derives active campaign IDs and their abort state, but
  does not unambiguously publish the bounded historical set of prior campaigns whose terminal
  hard-abort records T-F05g must verify (`tickets/T-F05i.md:35`).
- **Impact:** A fresh signed final snapshot can establish current state, but it cannot prove that the
  zero-generation/drain preconditions occurred before activation or that every prior campaign was
  terminal. The Test and Implement agents must invent an unscoped interface, and the advertised
  mechanical zero-overlap proof can pass without verifying the required history.
- **Exact repair:** Add a strict, create-only `RunnerRotationEvidence/v1` (or equivalently explicit
  staged verifier inputs) that binds the ordered pre-drain control artifact, zero-generation
  deployment artifact, terminal prior-campaign set, activation action/nonce, and final
  exactly-one-generation artifact by canonical hashes and monotonic signed timestamps/nonces.
  Give its schema/producer/verifier a bounded owner and unique tests/prompts. Make T-F05g's exact CLI
  consume and verify the entire chain, and make T-F05i publish the exact bounded historical
  terminal-campaign evidence the chain requires.

### I3 — T-F05j is not a half-day, single-concern swarm ticket

- **Evidence:** The repository's ticket law requires a ticket to be at most about half a day and
  split when criteria span multiple concerns
  (`.claude/skills/tdd-swarm/references/ticket-format.md:69-72`). T-F05j simultaneously owns five
  mandatory settings and URI parsing, a database migration, model/queue persistence and
  immutability/idempotency, a security-sensitive filesystem installer, startup and post-claim
  no-follow loading/pinning, and the two-source production refresh provider across seven
  implementation files (`tickets/T-F05j.md:8-16,33-40`).
- **Impact:** These are independently failure-prone configuration, storage migration, filesystem,
  and runtime-provider concerns behind one RED/freeze/GREEN loop and one test file. This exceeds a
  credible half-day scope, makes criterion-complete frozen tests unwieldy, and raises the chance of
  exhausting the three-attempt cap for process rather than feature difficulty.
- **Exact repair:** Split T-F05j into serialized bounded tickets with unique test scopes and five
  capable-model prompts each: (1) settings/reference plus immutable job/store/queue migration;
  (2) fixed-path secure install/load/pin lifecycle; and (3) the closed fresh-state provider,
  including I1's controller-observation source. Preserve their strict order before T-F05f, update
  every direct downstream dependency/input, recompute waves, and rerun collision checks.

### I4 — T-F05f's exact rejection message is incompatible with the queue interface it is allowed to use

- **Evidence:** T-F05f requires the existing terminal queue rejection to persist/use exact message
  `SMART session lease rejected`, and its frozen prompts test that exact value
  (`tickets/T-F05f.md:30`; `.tdd-swarm/prompts/T-F05f-test.md:2`). The existing queue sanitizes every
  non-empty caller failure message to `worker-supplied failure detail omitted` before persistence
  (`src/agentforge/storage/queue.py:209-216,532-575`). T-F05f may edit only
  `scoped_credentials.py` and `runner.py`, not the queue (`tickets/T-F05f.md:8-11`). T-F05j owns the
  queue earlier, but none of its acceptance criteria or prompts adds an allowlisted SMART rejection
  transition/message.
- **Impact:** The exact frozen assertion cannot pass against the real queue within T-F05f's scope.
  An implementer must bypass the queue abstraction, silently weaken the message requirement, or
  make an unauthorized upstream change.
- **Exact repair:** Either define the persisted message as the queue's existing safe constant, or
  add a preceding queue-owned criterion/test that permits exactly the code-owned SMART rejection
  constant without admitting arbitrary caller text. If the requested message is only an in-memory
  return/log message rather than the persisted queue field, say so explicitly and test both
  surfaces separately. Keep T-F05f dependent on the landed queue contract.

## Prior-finding closure

| Prior finding | Result |
|---|---|
| C1 — caller-composed rotation state instead of authoritative producers | **PARTIAL / NOT CLOSED.** T-F05h/T-F05i now own strict authenticated artifacts and downstream consumers reject combined state, but the production provider still lacks the controller-observation acquisition source needed to run T-F05h (I1), and rotation history is not mechanically bound (I2). |
| I1 — ephemeral 30-second observation pinned in immutable context | **CLOSED.** T-F05e pins only stable identity/trust bindings and validates newly authenticated observations separately; T-F05f refreshes them post-claim and per attempt. |
| I2 — missing Runner context delivery/provider interface | **PARTIAL / NOT CLOSED.** T-F05j defines the context ref/job/path/load lifecycle and provider shape, but the controller source is missing (I1) and the ticket violates the swarm sizing rule (I3). |
| I3 — Python 3.12/JSON Schema-invalid lexical contract | **CLOSED.** The plan uses Python 3.12 ASCII `re.fullmatch`, portable schema patterns, exact lengths/control rejection, and terminal CR/LF parity. Local Python 3.12.9/Draft 2020-12 checks passed. |
| I4 — validation required before the necessary queue claim | **PARTIAL / NOT CLOSED.** Atomic claim is now the sole explicit pre-validation mutation and all security-relevant hooks follow immediate validation, but the exact rejection contract cannot be implemented through the scoped queue interface (I4). |
| M1 — incomplete published fixture identity | **CLOSED.** T-F05d and affected tickets/prompts consistently use the exact ordered 12-field tuple, including target and surface IDs/versions. |

## Verified repaired behavior

- T-F04h remains an explicitly target-free smoke fixture; T-F05d is the sole SMART synthetic
  patient fixture authority.
- T-F05h verifies Ed25519 controller observations against a pinned manifest-bound trust root;
  T-F05i derives state inside one verified read-only repeatable-read transaction and attests it.
  T-F05e/T-F05g/T-F05c accept the two artifacts separately and recompute their hashes/attestations.
- The immutable context excludes observation hashes/times/counts/abort/drain/no-overlap state.
  Fresh validation has distinct `current_claim=None` and trusted non-serializable self-claim modes,
  rejects other leases/campaigns/current hard abort, and caches no successful observation.
- The context reference, fixed derived path, immutable job field, no-follow install/load rules,
  startup/post-claim pinning, and non-session compatibility are explicitly planned.
- T-F05f now permits only atomic claim before validation and gates campaign/attempt/evidence
  mutation, secret resolution, adapter/client construction, network, and spend.
- T-F05c/F06a and campaign/replay/stress/docs consumers have direct prerequisites for every
  T-F05d–T-F05j artifact they consume and use separate deployment/control source flags.

## Structural and hygiene checks

All checks were local and read-only; no repository test suite was run:

| Check | Result |
|---|---|
| Frontmatter, filename/ID parity, required sections, sequential AC IDs | PASS |
| Unique ticket IDs, dependency existence, acyclicity, and strictly earlier dependencies | PASS — 40 tickets, waves 0–22 |
| `TICKETS.md` wave membership parity | PASS — 40/40 |
| File/test scope overlap ancestry | PASS — 30 overlapping pairs, all ancestor-serialized |
| Same-wave unordered scope collisions | PASS — 0 |
| Unique lease-chain deterministic test scopes | PASS — 7/7 |
| Exact capable-model five-role lease-chain prompt sets | PASS — 35/35 |
| Prompt four-status contract, report paths, three-attempt cap, no-network/raw-secret/main rules | PASS |
| Operational prompt inventory | PASS — 150 prompts plus `PROMPT_TEMPLATE.md` |
| Direct downstream dependency and separate source-flag propagation | PASS |
| Stale combined-state CLI/setting/type and invalid `\A`/`\z` planning references outside the frozen prior review | PASS — none |
| Python 3.12 full-string and Draft 2020-12 terminal-newline lexical checks | PASS — Python 3.12.9 |
| Planning credential/private-key/provider-token scan | PASS |
| Repository high-risk private-key/provider-token scan | PASS |
| Planning trailing-whitespace, CRLF, and tracked `git diff --check` | PASS |

Inventory: **40 tickets, 150 operational prompts, waves 0–22**.

The repair-round-2 amendment is not dispatchable as written. Repair I1–I4, rerun the same
structural/hygiene checks, and obtain another independent zero-finding review before deterministic
implementation or any live/Railway/session activity.
