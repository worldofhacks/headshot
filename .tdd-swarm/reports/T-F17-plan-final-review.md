# T-F17 hosted runtime/provenance final plan review

Verdict: `REVIEW_CHANGES_REQUIRED`

Reviewed commit: `c488928`

## Prior-finding closure

| prior finding | status | result |
|---|---|---|
| F17-PR-1 authorized mutation path | closed | T-F17d now consumes the final T-F16 gateway, owns a versioned bounded mutation envelope, and tests seed/metadata/network-authority smuggling. |
| F17-PR-2 T-F16 dependency / Runner ownership | closed | T-F17d depends on accepted T-F16f and serializes `runner.py`; T-F17e is the next owner. |
| F17-PR-3 operational Orchestrator | incomplete | The snapshot/select/halt design is correct, but its versioned input/output contract files are outside T-F17d's scopes. |
| F17-PR-4 logical/physical correlation | incomplete | Pre-call context and composite keys are present, but retry identity and terminalization semantics remain contradictory. |
| F17-PR-5 capability identity | closed | Capability is content-addressed, generation-scoped, startup-superseded, migration-owned, and exact-match gated. |
| F17-PR-6 unknown cost | incomplete | The canonical measurement contract and T-F18j consumer work are correct, but the recorded cross-plan dependency creates a cycle. |
| F17-PR-7 100-case limit | incomplete | `400` / `300+F` truth is specified, but the authorization/API ceilings and spend/time ceilings are outside scope. |
| F17-PR-8 prompt endpoint identity | closed | Prompt retrieval is role/version/hash/config-addressed, organization-referenced, re-hashed, generic-failure, and no-store. |

The exact locked models, package-owned system prompts, `system` transport role, independent Judge,
provider-confirmed observed lineage, configured-versus-observed UI semantics, and human/deployment
gates remain correct.

## Exact blockers

### FINAL-1 — T-F18j dependency cycle

The repaired T-F17 plan and TICKETS addendum make T-F18j depend on accepted T-F18i, then make
T-F17e depend on T-F18j and T-F17f depend on T-F17e:

```text
T-F18i -> T-F18j -> T-F17e -> T-F17f
```

The current console plan on `codex/console-pages-remediation-plan` makes T-F18i depend on T-F17f.
The combined graph is therefore:

```text
T-F17f -> T-F18i -> T-F18j -> T-F17e -> T-F17f
```

The console branch's repaired T-F18j ticket already has the acyclic correct dependency:
`depends_on: [T-F17b, T-F17c]`, and wave 29 precedes T-F17e. T-F17's plan/table/addendum must remove
`accepted T-F18i` from T-F18j and point to that exact current ticket. The intended order is:

```text
T-F17b + T-F17c -> T-F18j -> T-F17e -> T-F17f -> ... -> T-F18i
```

### FINAL-2 — Operational Orchestrator contracts are not in T-F17d's write scope

T-F17d now requires a materially expanded `OrchestrationSnapshotV1` and a new exact
`select(candidate_id, reason_codes) | halt(reason_code)` output. The existing
`src/agentforge/contracts/v1/orchestration_snapshot.json` lacks the candidate identities/hashes,
expiry, scan-plan revision, unknown-cost state, and remaining provider/target/token/time fields.
The existing `campaign_directive.json` cannot represent the new select/halt union.

T-F17d's file scopes list only the mutation-envelope schemas plus the registry. An implementer
cannot lawfully change the snapshot schema or add the hosted decision schema, and inline schemas
would violate the PRD's versioned inter-agent-contract requirement.

Repair: add packaged and root/public scopes for the upgraded orchestration snapshot and a versioned
hosted orchestration decision (with migration note/contract tests), or create a predecessor ticket
that T-F17d depends on.

### FINAL-3 — One immutable physical context cannot identify transport-internal retries

T-F17b correctly requires one committed pre-call invocation per physical sequence. T-F17c still
passes one singular Runner-created invocation context into `OpenRouterTransport.invoke`, while the
transport owns its retry loop. A retry therefore needs a second immutable context committed before
its second reservation/network call; reusing the first violates uniqueness and creating identity
afterward violates the pre-call invariant.

T-F17b AC-7 also says every terminal provider event and logical execution terminalization commit
atomically, but a retryable first physical event must leave the logical execution running until the
final physical attempt.

Repair: specify a Runner-owned `begin_physical_attempt(logical_context, sequence)` callback/factory
used before every reservation, and define atomic transitions as:

- each physical terminal event commits with its invocation;
- retryable non-final events leave the logical execution running;
- only final success/terminal failure atomically terminalizes the logical execution;
- crash recovery emits `outcome_unknown` without another call.

Freeze tests for two distinct pre-call invocation rows in retry-then-success and for the logical
status between attempts.

### FINAL-4 — The 100-case profile cannot pass current authorization/API/spend ceilings within scope

T-F17c owns `hosted.py`, so it can raise `HOSTED_MAX_PHYSICAL_CALLS`, but a 400-call
`HostedRunBinding` is still rejected at `src/agentforge/target/spec.py` and
`src/agentforge/api/router.py`; `src/agentforge/api/read_models.py` also caps the field at 56.
Those files and their target/API tests are not in T-F17c's scopes.

The same profile still inherits the hard global `HOSTED_MAX_MEASURED_USD = 5`. The repaired plan
requires reserving the profile's derived token/cost/time maximum but defines only the physical-call
formula. It does not prove that the four locked models can fit the current spend/time ceilings or
define safely raised, authorization-bound values. Merely raising the call constant cannot produce
an admissible 100-case run.

Repair: add a focused authorization-contract ticket (or expand T-F17c) owning
`target/spec.py`, API input/read models, hosted limits, serialization/contracts, and their tests.
Define and test exact profile-specific call, token, measured-spend, timeout, retry-zero, and
concurrency-one ceilings. All layers must accept 400 only for the exact hosted-100 profile and retain
the lower legacy bound elsewhere.

## Final gate

Do not dispatch T-F17 RED until these four blockers are repaired and the combined T-F16/T-F17/T-F18
graph is mechanically validated as acyclic.
