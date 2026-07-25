# Hosted 100-case capacity preflight — 2026-07-24

Status: **BLOCKED before provider or target I/O**

This is a source/configuration admission audit, not a load test, campaign result, provider call,
deployment assertion, or replacement for the security owner's frozen corpus and performance
analysis. It inspected committed candidate source through
`a1abbc41dd7973a7c6e63e7bf054369e15842cbc` and the retained public-catalog artifact.
No credential was read and no provider or target request was made.

## Closed-envelope result

| Gate | Required 100-case shape | Candidate/configured authority | Result |
|---|---:|---:|---|
| Frozen corpus | Exact owner-authored 100-case ID and SHA-256 | Not integrated | blocked |
| Hosted physical calls | 100 Orchestrator + 100 Red Team + 100 Judge + up to 100 Documentation = 400, zero provider retries | Source hard maximum 400; retry-one expands to 800 and is refused | source-tested only |
| Hosted input/output/reasoning tokens | 18,601,600 / 1,024,000 / 2,150,400 at the current policy bounds | No final 100-case configuration is staged | blocked |
| Encoded Red-Team input | Must fit the authorization-bound policy before any side effect | Default policy is 4,096; current canonical 9-case requests measure 5,399–5,526 and 14-case full-scan requests measure 5,336–9,802 under the conservative byte bound | correctly refused |
| Provider reserved-spend envelope | Human-selected exact cap sufficient for the intended completion claim | Source exactly sums worst-case reservations across all required attempts; current role caps are $1.50 / $1 / $4 / $1 and global cap is $10 | correctly refused |
| Target logical/physical work | 100 logical cases / 121 physical sends / zero target retries | Live target v1.0.0 ceiling is 40 / 60 / one retry | blocked |
| Target dispatch budget | At least $1.21 at the configured $0.01-per-send accounting, with an exact approved decimal-safe cap | Live ceiling is $1 | blocked |
| Target time | 8,737.168 seconds for 121 sends at the retained 72,208-millisecond observation, before model/queue/database time | Live target ceiling is 1,800 seconds | blocked |
| Authorization window | Strictly greater than selected run timeout plus 300-second start margin | Standard remains max grant 3,600; source-tested `staging_extended` is opt-in, staging-campaign-only, max run/grant 14,400/14,701, and appears only when the target ceiling needs it. Live target v1.0.0 remains 1,800, so it exposes no extended option | blocked |
| Deployment | Exact green release at migration `0018` | Railway remains on `23490ea` / `0013` | blocked |

The token totals are deterministic multiplication of
`DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(case_count=100)` with zero retries. They
are not measured provider usage. Documentation is reserved for every case because the trusted
confirmed-finding count is not known before the frozen run.

## Price versus authorization capacity

The public catalog observed maximum-token per-attempt costs of `$0.642048`, `$0.0130048`,
`$0.2274`, and `$0.180224` for Orchestrator, Red Team, Judge, and Documentation. Repeating those
dated rates across 100 calls of every role is `$106.26768`. This remains a rate sensitivity, not a
bill.

The artifact-configured price ceilings reserve `$1.16736`, `$0.34816`, `$3.024`, and `$0.98304`
per attempt. One hundred of each is `$552.256`. Those reservations are deliberately conservative
authorization exposure, not forecast spend. Both views exceed at least one current aggregate
role/global kill switch. Candidate source computes these cumulative reservations with fail-closed
exact-decimal arithmetic and rejects insufficient per-role authority as
`hosted_role_usd_cap_incompatible` or insufficient global authority as
`hosted_global_usd_cap_incompatible` before provider I/O. It also refuses a reservation that cannot
be represented exactly rather than rounding it into authority. A lower cap may validly hard-abort,
but it cannot be described in advance as completion-capable for the 100-case worst-case envelope.

## Exact-input correction

Before `8c21d2d`, the transport could silently reserve
`max(policy_input_bound, encoded_message_bound)` and send a message larger than the policy identity
authorized. Candidate source now refuses before concurrency, pacing, credential resolution, ledger
reservation, provider lineage, Langfuse observation, or HTTP when the conservative encoded-message
bound exceeds the policy bound. The ledger reserves exactly the authorization-bound value.

This correction intentionally makes the default 4,096-token Red-Team policy non-executable for the
current canonical requests. Raising it without the missing frozen 100 request shapes would invent an
authority value and change the generation-policy SHA-256. The final policy must be derived from the
owner's exact corpus, registered append-only, and rebound through a new configuration and campaign
authorization.

## Per-send deadline correction

Candidate commit `b14d2bd` anchors one start-plus-run-timeout deadline and, before every
physical provider attempt or target send, re-proves the queue claim and immutable authorization.
The exact configured transport timeout must finish strictly before the run deadline, approval
expiry, and any delegated-session expiry; equality refuses. Provider refusal precedes credential,
lineage/ledger, physical-attempt observation, and HTTP. Target reservation remains the final callback
before adapter I/O, preserving ambiguous-send no-replay semantics. The focused 185-test suite
passes.

This prevents an already-too-late external call; it does not make the four-hour option a completion
estimate, extend the current 1,800-second target, provide the missing credential lease, or constitute
deployment/live evidence.

## Required next authority

Do not launch until all of these are present together:

1. the security owner's frozen corpus ID/hash and final Judge/oracle identity;
2. a new generation-policy hash whose per-role bounds cover every exact encoded request;
3. an append-only schema-v2 configuration with 100 calls per role, 400 global calls, zero provider
   retries, exact cumulative token ceilings, human-approved role/global USD caps, rate, concurrency,
   timeout, and distinct secret references;
4. a fresh redacted exact-route catalog preflight for that configuration;
5. a new immutable target version whose exact 100/121/zero-retry/budget/rate/timeout ceilings cover
   the frozen manifest;
6. a still-bounded authorization window and credential lease that outlive the selected timeout;
   if the staging-only extended profile is needed, a new target version whose timeout exceeds the
   standard window and an explicit browser selection are required;
7. one exact green release deployed to staging and migrated through `0018`; and
8. the normal distinct-human approval and launch grant.

An aborted or partial run remains useful abort-control evidence, but it is not the required completed
100-case security or performance result.

The source-tested staging-only four-hour candidate window would leave 5,662.832 seconds for
300–400 provider calls plus queue/database work after the target-only baseline. That is only
18.876 seconds per provider call at 300 calls or 14.157 seconds at 400 calls before other overhead,
so four hours is a bounded admission option, not evidence that completion will fit. It is not
available to the current 1,800-second target catalog and is not deployed. Per-call target and
provider timeouts are safety maxima rather than an ETA.
