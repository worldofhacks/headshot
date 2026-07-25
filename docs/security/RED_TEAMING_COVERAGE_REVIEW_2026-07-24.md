# Red-teaming coverage review

**Date:** 2026-07-24
**Scope:** AgentForge / Adversarial Machine repository, deployed-platform design, LLM
evaluation corpus, Judge, target adapter, regression path, security-tool integrations,
and Burp-style workbench claims.
**Method:** Read-only code and evidence review plus local validation. No live campaign,
active scan, target request, Clerk administration, deployment change, or publication action
was performed.

## Executive verdict

AgentForge has a strong **governance and evidence foundation**, but it is not yet a
full-spectrum LLM red-team platform and it does not yet provide feature parity with Burp
Suite.

The strongest implemented areas are exact-scope authorization, a gateway-only target exit,
synthetic-data controls, bounded execution, independent fail-closed adjudication,
content-addressed evidence, two-person publication controls, and durable campaign
orchestration. Those are unusually good foundations.

The limiting fact is efficacy:

- The production Runner replays a fixed 14-case corpus; it does not use the implemented
  mutation component, and hosted attack generation raises `NotImplementedError`.
- The corpus exercises only three of the six required threat categories. Five of its 14
  cases are additional prompt-injection transformations.
- Only two cases have a currently runnable exact canary. With the current Judge, the other
  12 cases cannot receive a decisive behavioral verdict unless trusted external
  instrumentation supplies an oracle result.
- The checked-in LLM seed results are all `NOT_EXECUTED`; there is no checked-in live
  LLM-campaign result.
- Garak, PyRIT, Giskard, and Promptfoo are integrated safely, but only a very small fraction
  of their useful attack capabilities is exercised.
- The Burp-named workbench capabilities are analogies over logs, replay, and advisory tools.
  There is no intercept/edit/forward proxy, arbitrary Repeater, payload-position Intruder,
  active authenticated scanner, token-randomness Sequencer, byte/word Comparer, OAST
  callback service, browser DOM instrumentation, WebSocket testing, or API-schema scanner.

The correct current label is:

> **Governed, partially implemented LLM evaluation platform with a strong safety control
> plane—not yet live-evidenced, autonomous, comprehensive, or continuously verified red
> teaming.**

## Validation performed

| Check | Result |
|---|---|
| Python lint, formatting, corpus validation, duplicate detection, tests, secret scan via `scripts/check.sh` | Passed; 1,001 tests passed, 3 skipped |
| React/Vitest suite | Passed; 75 tests |
| Console TypeScript/Vite build and source/bundle policy checks | Passed |
| Browser smoke suite | Passed; 4 tests |
| `npm audit --audit-level=high` | 0 known vulnerabilities |
| Gitleaks committed-history scan | 0 findings |
| Judge calibration with `--require-pass` | **Failed as designed:** 60% agreement, 33.3% false-negative rate, 60% abstention |

The ordinary test suite passing does not mean the Judge is enabled. The test suite currently
asserts that the non-oracle calibration gate fails
(`tests/test_judge_calibration.py:43-57`).

## Current capability scorecard

| Area | Status | Basis |
|---|---|---|
| Authorization and safety envelope | Strong foundation | Exact target/surface/corpus binding, synthetic-only assertion, caps, two-person controls |
| Multi-agent separation | Strong foundation | Red Team, Recorder, Judge, Documentation responsibilities are structurally distinct |
| Evidence integrity and reporting | Strong foundation | Append-oriented evidence, reread/hash verification, normalized and publication-gated findings |
| Live LLM test evidence | Missing | All authored seeds remain `NOT_EXECUTED`; `evals/results/` records no campaign results |
| Dynamic adversarial search | Not operational | Standalone mutation is unwired; hosted generation is unimplemented |
| Decisive adjudication | Major blocker | Two runnable canaries; non-oracle Judge abstains; calibration gate fails |
| LLM risk breadth | Partial | Three threat categories; mostly chat-simulated coverage; LLM09 has no authored case |
| Existing LLM tool utilization | Shallow | Five imported prompt-injection candidates across three tools; Giskard imports zero |
| Burp-style web/API workflow | Partial | Useful ledger, bounded replay, passive ZAP, and reports; most interactive/active capabilities absent |
| Continuous regression | Planned/partial | Plans and evaluation contracts exist; automatic replay execution is not wired end to end |
| Runtime operational safety | Needs hardening | Persisted abort cadence, DB role use, DNS pinning, lease recovery, and retry ambiguity need fixes |
| Deployment/release proof | Incomplete | Requirements matrix still marks Railway/Clerk/two-user/live-loop proof partial or blocked |

## Detailed findings

### RT-01 — High: coverage is mapped, not demonstrated

All nine authored attack cases have `execution_status: NOT_EXECUTED`, and
`evals/results/README.md:1-18` explicitly says no campaign-result JSON exists. A separate
passive ZAP artifact is useful web evidence, but it is not LLM behavioral evidence.

The runtime coverage threshold is also narrower than the platform's public taxonomy:

- required Web mappings:
  `A01, A03, A04, A06, A07, A09, A10`;
- required LLM mappings:
  `LLM01, LLM02, LLM03, LLM05, LLM06`;
- required categories:
  `prompt_injection, data_exfiltration, tool_misuse`.

Those sets are defined at `src/agentforge/api/postgres.py:77-79`. A campaign can therefore
look “covered” without LLM04, LLM07, LLM08, LLM09, LLM10, Web A02/A05/A08, or the three
unused platform threat categories.

**Improve:** replace the binary coverage claim with explicit states:

1. mapped;
2. case authored and schema-valid;
3. executable on a real target surface;
4. authorized;
5. dispatched;
6. live-observed;
7. oracle-backed;
8. decisively adjudicated;
9. regression-admitted and replayed.

Only states 6–9 should count as demonstrated security coverage.

### RT-02 — High: the Judge cannot adjudicate most of the full-scan corpus

The deterministic Judge intentionally emits `INDETERMINATE` when no canary or trusted oracle
hits (`src/agentforge/agents/judge/judge.py:129-146`). That is safe, but it is not useful
enough for broad red teaming.

Current facts:

- exact substring matching is the implemented trusted oracle;
- only PI-001 and DX-001 have directly runnable canaries;
- all five tool-generated cases explicitly use an unavailable `none` oracle
  (`src/agentforge/campaign/corpus.py:200-210`);
- the current 15-label calibration produces 9 agreements, 3 false negatives, and 9
  abstentions (`tests/test_judge_calibration.py:43-57`);
- `scripts/run_judge_calibration.py --require-pass` fails.

The fail-closed behavior is a strength. The capability gap is that **12 of 14 cases will
normally remain non-decisive** with the current evidence path.

**Improve:** add trusted, category-specific instrumentation before adding a semantic Judge:

- tool-call name, arguments, authorization decision, and side-effect recorder;
- patient/tenant and retrieval-scope traces;
- pre/post state diff and write oracle;
- RAG source/document/chunk identifiers and metadata-filter decisions;
- renderer/sink canaries for HTML, Markdown, URLs, SQL, templates, and commands;
- request, tool-call, token, latency, and cost counters;
- semantic/partial/encoded leakage detectors with human-labeled calibration.

Keep deterministic oracle precedence. Enable a model Judge only after the exact identity
passes the versioned calibration gate and receives the required human enablement.

### RT-03 — High: the LLM taxonomy is incomplete and some mappings are nominal

The schema knows all OWASP LLM Top 10:2025 risks and all six PRD threat categories
(`src/agentforge/evals/validation.py:122-155`), but the executable corpus does not.

| OWASP LLM risk | Actual current depth |
|---|---|
| LLM01 Prompt Injection | Best-covered: direct, indirect, and multi-turn chat prompts plus five transformed candidates. “Indirect” is not exercised through a real ingestion/RAG route. |
| LLM02 Sensitive Information Disclosure | Three cases; one decisive cross-patient canary. No partial, semantic, multilingual, or encoded-leakage oracle. |
| LLM03 Supply Chain | Nominal poisoned-content mapping; no model, provider, plugin, adapter, prompt-template, or dependency-integrity scenario. |
| LLM04 Data and Model Poisoning | Nominal mappings only; no ingest/index/persist/retrieve/rollback lifecycle. |
| LLM05 Improper Output Handling | Nominal tool/write case; no real renderer or executable sink harness. |
| LLM06 Excessive Agency | Three good designs, but tool/scope/side-effect instrumentation is absent. |
| LLM07 System Prompt Leakage | One exact canary; no partial reconstruction, obfuscation, or policy-inference testing. |
| LLM08 Vector and Embedding Weaknesses | Nominal mappings; no vector store, metadata filter, collision, poisoned-neighbor, or cross-tenant index test. |
| LLM09 Misinformation | No authored case. |
| LLM10 Unbounded Consumption | One recursive-tool-call design with a pending oracle; no context bombs, amplification, concurrency, large-file, timeout, or RAG-cost cases. |

The six-category PRD taxonomy is only half populated:

| Category | Corpus status |
|---|---|
| prompt injection | 8/14 cases |
| data exfiltration | 3/14 cases |
| tool misuse | 3/14 cases |
| state corruption | 0 |
| denial of service | 0 |
| identity/role exploitation | 0 |

Because this is itself a multi-agent platform, add the
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
alongside OWASP LLM. The current repository has no ASI01–ASI10 mapping. Priority agentic
cases are goal hijack, tool misuse, identity/privilege abuse, agentic supply chain,
unexpected code execution, memory/context poisoning, insecure inter-agent communication,
cascading failures, human-agent trust exploitation, and rogue-agent behavior.

**Improve:** build cases from a surface × principal × state × attack × oracle matrix, not a
target count. Every applicable risk should include boundary, invariant, and regression
cases, positive and negative controls, and a real observation point.

### RT-04 — High: feedback-driven mutation is not part of the production campaign

`mutate()` is implemented and tested at
`src/agentforge/agents/red_team/mutation.py:41-85`, but the durable Runner constructs
`SeedReplayRedTeam` (`src/agentforge/runner.py:269,285-288`) and selects exact reviewed
cases (`src/agentforge/runner.py:629-693`). The handoff correctly forbids an unapproved
mutation because authorization is bound to the corpus hash
(`src/agentforge/agents/red_team/handoff.py:1-5`).

The hosted generator boundary raises `NotImplementedError`
(`src/agentforge/agents/red_team/providers.py:271-282`).

**Improve:** preserve the authorization invariant with a two-stage loop:

1. generate/mutate candidates without target authority;
2. validate, normalize, minimize, deduplicate, score novelty, and content-address them;
3. obtain human review for the new candidate bundle;
4. bind the new corpus hash into fresh exact-scope authorization;
5. dispatch through the existing Policy Gateway;
6. feed oracle-backed partial success and coverage gaps into the next candidate batch.

Never mutate silently inside an already authorized run.

### RT-05 — High: existing LLM tools are used far below their useful depth

The existing isolation and provenance controls are good. Tool output remains advisory and
cannot authorize traffic or issue verdicts. The problem is breadth.

| Tool | Current use | Highest-value next use |
|---|---|---|
| Garak 0.15.1 | One `dan.Dan_11_0` probe, one generation, repeat generator | Allowlisted probe matrix for injection/jailbreak, leakage, encoding/obfuscation, hallucination, and target-relevant unsafe behavior; normalize every candidate and score novelty |
| PyRIT 0.14.0 | Base64, ROT13, ASCII-smuggling converters | Bounded multi-turn Crescendo/TAP/Skeleton Key orchestration, scorers as advisory signals, composite converter chains, response-driven attack refinement |
| Giskard 1.0.0b3 | Packaged scenario loader; zero explicit imported candidates | Real owned-target/RAG scan, resolved scenarios, GOAT/Crescendo/GCG where supported, and export into reviewed bundles |
| Promptfoo 0.121.19 | One pre-authored local-provider test | Governed red-team plugins/presets, multi-turn assertions, target provider behind the gateway, deterministic assertions, and normalized results |
| ZAP 2.17.0 | Passive baseline; CI scans an isolated fake site | Automation-framework plan with API import, authenticated/AJAX crawl, passive rules, then separately authorized active profiles |
| Semgrep 1.170.0 | Four narrow custom rules | Framework-aware and taint rules for FastAPI/React, auth boundaries, SSRF, secret/log sinks, dangerous rendering, SQL construction, subprocesses, and unsafe deserialization |
| pip-audit/npm audit/Gitleaks | Real CI gates | Retain; ingest signed results and provenance into the platform rather than leaving them only as CI artifacts |

The current limitations are already documented at
`docs/security/LLM_TOOLCHAIN.md:22-33`; the implementation should make that honest scope
visible in the UI.

### RT-06 — High: Burp-style names currently overstate feature equivalence

PortSwigger defines Burp Proxy as interception and modification, Repeater as manual
modify/resend, Intruder as payload-position automated attacks, Sequencer as token-randomness
analysis, Comparer as a byte/word diff, and Collaborator as OAST. See the official
[Burp tools inventory](https://portswigger.net/burp/documentation/desktop/tools).

| Burp capability | AgentForge status | Gap |
|---|---|---|
| Dashboard / Target / scope | Partial-to-strong | Good target/campaign registry; no discovered sitemap/attack-surface model |
| Browser | Missing | No instrumented testing browser |
| Proxy / Logger / Inspector | Partial | Sanitized outbound ledger and previews; no listener, intercept, raw edit, forward/drop, match/replace, arbitrary browser capture, or WebSocket history |
| Repeater | Partial | Governed case replay; no arbitrary captured-message editor/resend or request sequences |
| Intruder | Partial | Reviewed prompt candidates; no payload positions, attack modes, parameter discovery, extract/grep, resource pools, or combinatorial fuzzing |
| Scanner | Partial | Passive ZAP plus Judge; no authenticated active web/API scan |
| Crawler/site map | Minimal | One-minute bounded classic ZAP spider; no authenticated/AJAX crawl, form handling, or reusable site map |
| API/OpenAPI/Postman/GraphQL | Missing | No definition import, operation enumeration, schema-derived payloads, or API scan |
| WebSocket/SSE testing | Missing | No target adapter, message editor, or attack suite |
| Authentication/session handling | Minimal | Credential transport and cookie persistence exist; no login macro, multi-principal matrix, JWT/cookie tests, fixation, rotation, revocation, or expiry suite |
| Access control | Partial | A few cross-patient/write designs; no systematic BOLA/BFLA/forced-browsing role matrix |
| Sequencer | Missing under that meaning | Current “Sequencer” is conversation ordering, not randomness analysis |
| Decoder | Partial | Three PyRIT transforms; no generic URL/HTML/hex/JWT/binary/gzip/hash transformation workbench |
| Comparer | Missing under that meaning | Judge/resilience comparison is not arbitrary byte/word HTTP diff |
| Collaborator/OAST | Missing | Synthetic response canaries are not DNS/HTTP callback observation |
| DOM Invader/Clickbandit/Infiltrator | Missing | No DOM sink, postMessage, prototype-pollution, clickjacking, or instrumented-runtime testing |
| Message editor / Organizer / Search | Minimal | No reusable raw-message workbench, annotations, investigation queue, or cross-artifact search |
| Extensions/BChecks | Limited | Code-owned Python adapters, not a runtime extension/check interface |
| Reporting | Strong | Structured, sanitized, human-gated findings; no complete executive/technical HTML/PDF export found |

`src/agentforge/security_tools/workbench.py:33-116` calls several analogous workflows
“operational.” Until the literal capability exists, label them `partial`, `analogy`, or
`planned`. In particular, current “Sequencer” and “Comparer” should be renamed or
implemented according to their Burp meanings.

**Improve in this order:**

1. governed request capture, safe-field editor, resend, history, annotations, and diff;
2. payload positions, transformations, extraction, concurrency/rate pools, and minimization;
3. OpenAPI/Postman import and schema-derived API cases;
4. synthetic multi-principal authentication/session/access-control matrix;
5. authenticated/AJAX crawl and separately authorized active ZAP;
6. private per-attempt OAST with random tokens, TTL, exact-scope callback evidence, and
   no-PHI enforcement;
7. WebSocket/SSE and browser DOM/output-sink testing.

True “most of Burp” coverage either requires integrating Burp itself or implementing these
behaviors explicitly. Similar labels are not parity.

### RT-07 — High: the tested target surface cannot exercise several claimed risks

The durable target adapter sends one chat message with `session_id` and `message`
(`src/agentforge/target/openemr_adapter.py:353-387`). The synthetic catalog exposes one
POST chat surface and disables upload/write capabilities
(`src/agentforge/target/catalog.py:243-268`).

As a result, upload/RAG poisoning, retrieval metadata bypass, stored memory poisoning,
actual tool invocations, writes, recursive tool behavior, and executable output sinks are
currently simulated in chat rather than directly exercised and observed. The synthetic
cassette also emits a referenced canary by construction
(`src/agentforge/target/cassette_adapter.py:24-40`); that validates platform plumbing, not
target resistance.

**Improve:** register separate, versioned surfaces for:

- ingestion/upload and indexing;
- retrieval/query with source and scope telemetry;
- conversation memory and session/principal switching;
- tool discovery, selection, arguments, authorization, execution, and side effects;
- controlled write sandbox;
- rendered HTML/Markdown/link output and downstream sinks;
- streaming/SSE/WebSocket behavior if present.

Mark chat-only approximations as `simulated_surface` and exclude them from demonstrated
coverage for the real surface.

### RT-08 — Medium: regression planning exists, but continuous execution does not

`RegressionReplayGate` creates content-addressed blocked plans and evaluates persisted
observations (`src/agentforge/regression/replay.py:33-242`). The Scheduler only materializes
authorization-blocked target-version plans
(`src/agentforge/scheduler.py:1-7,150-170`). No end-to-end Runner/API path was found that
authorizes and executes those plans.

The current campaign path also evaluates new findings with:

- `reproduction_attempted=False`;
- `deterministic_reproduction=False`;
- `passes_for_right_reason=False`;
- `human_approved=False`.

See `src/agentforge/runner.py:838-846`.

**Improve:** wire admitted finding → reproduction job → human approval → exact replay
authorization → repeated Runner execution → oracle-based right-reason assessment →
target-version reappearance alert. Preserve the current fail-closed admission gate.

### RT-09 — High: persisted abort state is not rechecked before every physical request

The Runner's persisted gate refreshes the lease and re-reads approval/scope/abort state
(`src/agentforge/runner.py:716-736`), but the coordinator invokes it only once per logical
attempt (`src/agentforge/campaign/coordinator.py:390-425`).

A multi-turn attempt then paces and sends each physical message
(`src/agentforge/policy/gateway.py:338-419`), while retries check only in-memory caps before
`adapter.send()` (`src/agentforge/policy/gateway.py:421-468`). An operator abort or
authorization change during pacing/backoff can therefore still be followed by another
outbound request.

**Improve:** make the persisted dispatch gate a Policy Gateway dependency and invoke it
immediately before every physical `adapter.send()`, including every retry. Test abort during
inter-turn pacing and retry backoff.

### RT-10 — High: per-agent database roles are design/test controls, not runtime isolation

The database roles are `NOLOGIN` and are described as exercised through `SET ROLE`
(`src/agentforge/storage/roles.sql:8-20`). Production code contains no `SET ROLE`; the
campaign runtime creates one engine from `DATABASE_URL`
(`src/agentforge/campaign/runtime.py:68-81`), and the Runner/coordinator use that engine for
orchestration, persistence, reread, and Judge data.

If the base runtime login owns tables or inherits broad grants, the intended Red
Team/Recorder/Judge database separation is not enforced at the production query boundary.

**Improve:** use separate least-privilege service connections or transaction-scoped
`SET LOCAL ROLE` from a non-owner, `NOINHERIT` login. Add production-composition tests that
prove:

- Red Team cannot read or mutate authoritative evidence;
- Recorder can insert but not update/delete;
- Judge can read required evidence but cannot write campaign or publication state;
- connection-pool reuse cannot retain a prior role.

### RT-11 — High: destination validation has a DNS-rebinding time-of-check/time-of-use gap

The Runner resolves and rejects private addresses
(`src/agentforge/runner.py:176-193`). The HTTP client subsequently resolves the hostname
again while connecting (`src/agentforge/target/openemr_adapter.py:194-207`). A DNS answer
can change between those operations.

**Improve:** connect to a validated, pinned address while preserving TLS SNI/hostname
verification, verify the connected peer, and enforce an outbound network policy that blocks
private/link-local/metadata ranges. Revalidate on each new connection and redirect; redirects
should remain denied.

### RT-12 — Medium: crashed Runner work can remain leased indefinitely

`PostgresJobQueue.reap_expired()` is implemented
(`src/agentforge/storage/queue.py:583-621`) but is referenced only from tests. The production
Runner loop claims work and polls; it does not reap expired leases
(`src/agentforge/runner.py:960-1047`).

**Improve:** run bounded, concurrency-safe reaping in a private worker/scheduler loop and add
crash/restart tests that prove requeue/dead-letter behavior and campaign-state reconciliation.

### RT-13 — Medium: ambiguous POST failures can duplicate a conversational turn

The base `AdapterError` is retryable
(`src/agentforge/target/base.py:20-24`). Generic transport failures around an HTTP POST are
mapped to retryable errors (`src/agentforge/target/openemr_adapter.py:208-238`) and may be
sent up to three times (`src/agentforge/policy/gateway.py:421-468`). A connection failure can
be ambiguous: the target may have processed the request before the client lost the response.

**Improve:** retry only failures known to occur before request transmission, or add a
target-supported idempotency key bound to run/attempt/turn. Record the key in evidence and
verify duplicate suppression.

### RT-14 — Medium: readiness, public-shell, authorization-record, and evidence status need tightening

- Web passes `runner_available=True` to the backend
  (`src/agentforge/app.py:117-123`), while readiness checks DB/schema, console, and local
  security config—not a fresh Runner heartbeat (`src/agentforge/readiness.py:78-100`).
- Any HTML path outside a few exclusions receives the public SPA shell
  (`src/agentforge/web.py:316-333`), broader than the enumerated minimal shell rule in
  `docs/deployment/RAILWAY.md:94-105`.
- `ownership_authorization_ref` is validated only as a string beginning
  `authorization://` (`src/agentforge/target/catalog.py:95-104`).
- `docs/evidence/zap/README.md` records a live passive target scan, while
  `docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md:97-103,201-205` still says live-target ZAP
  remained blocked. This is evidence/status drift.

**Improve:** require fresh private-service heartbeat/catalog/corpus/queue readiness; enumerate
public auth-shell routes; bind ownership authorization to a signed/scoped/expiring record;
and generate status pages from authoritative evidence records rather than hand-maintained
claims.

## Prioritized delivery plan

### Gate 0 — Make execution safe and claims truthful

1. Recheck persisted abort/authorization/lease state before every physical request and retry.
2. enforce the per-agent database role boundary in production composition;
3. close DNS rebinding and ambiguous POST retry behavior;
4. run expired-lease recovery;
5. expose multi-state evidence coverage and downgrade inaccurate “operational” labels;
6. require `run_judge_calibration.py --require-pass` for any non-oracle Judge activation;
7. finish Railway/Clerk/private-service/two-user proof before claiming a deployable live loop.

### Gate 1 — Make LLM results decisive

1. add trusted tool, state, RAG, sink, identity, and consumption instrumentation;
2. expose the real ingestion, retrieval, memory, tool, write, and output surfaces;
3. add cases for all six PRD categories, all applicable OWASP LLM risks, and OWASP Agentic
   Top 10 risks;
4. run an exactly authorized campaign against the deployed live target using seeded
   synthetic non-PHI records in that target—not fixture adapters—and retain normalized,
   content-addressed evidence;
5. calibrate category-specific semantic assessment only where deterministic oracles cannot
   decide.

### Gate 2 — Use the existing tools deeply

1. expand the allowlisted Garak probe matrix;
2. use PyRIT multi-turn orchestration and composite transforms;
3. execute real Giskard owned-target/RAG scans;
4. run Promptfoo red-team plugins and assertions through the governed target boundary;
5. ingest every native artifact and normalized candidate/finding into the platform;
6. add target-version/tool-version drift detection and reproducible pinned runs.

### Gate 3 — Build literal Burp-equivalent workflows

1. capture/editor/replay/diff workbench;
2. payload-position fuzzer with extraction and minimization;
3. authenticated API discovery/import/crawl/scan;
4. session and multi-principal access-control testing;
5. private OAST;
6. WebSocket/SSE and browser/DOM testing;
7. continuous regression execution and reappearance alerts.

## Definition of “full LLM red teaming”

Do not declare this review closed until all of the following are evidenced:

- Every applicable target surface is registered and attacked through the Policy Gateway.
- Every applicable OWASP LLM 2025, OWASP Agentic 2026, and OWASP Web category has at least
  one executable boundary, invariant, and regression test—or a documented
  not-applicable rationale approved by a human.
- Every case has a trusted observation mechanism; cases without decisive evidence are shown
  as indeterminate, never passing.
- Mutation/tool generation produces reviewed, content-addressed candidate corpora under new
  authorization.
- All existing tool integrations execute meaningful target-relevant matrices and their
  results enter the evidence and finding system.
- The Burp comparison is literal and test-backed, not name-based.
- A human-approved campaign against the exact live URL, using seeded synthetic non-PHI live
  records and provisioned test principals, produces persisted evidence, independent
  verdicts, and regression candidates.
- Mocks, cassettes, fixture adapters, fake/loopback targets, in-process receivers, local
  harnesses, and simulated artifacts never count as operational, regression, or closure
  evidence.
- Confirmed findings are deterministically reproduced, fixed for the right reason, replayed
  on target-version changes, and monitored for reappearance.
- The release commit is pushed to both `origin/main` and `gitlab/main`, the refs resolve to
  the same commit, and both CI systems are green.

## External baselines

- [Canonical Burp Suite tool inventory](https://portswigger.net/burp/documentation/desktop/tools)
- [Burp testing workflow](https://portswigger.net/burp/documentation/desktop/testing-workflow)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
