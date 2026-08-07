# Generative red-teaming — the governed two-stage loop

**Status: Tier 1 stages 1–3 implemented and tested. Stage 4 (dispatch) is not wired. Tier 2
(multi-round feedback) is NOT built — it is next.**

Nothing in this document describes an executed live campaign. No generated case in this repository
has been dispatched at a target, and no generated case has produced a verdict. What is implemented
is the governed *path* a generated attack must traverse before it could be.

## The invariant

> Every generated attack passes **curate → human review → new corpus hash → new authorization**
> before it touches the target.

This exists because of a real, previously-identified gap. The 2026-07-25 coverage review recorded
that hosted generation was implemented but **structurally undispatchable**: the coordinator
requires every proposal to equal the reviewed corpus byte-for-byte, so a generated attempt falls
outside the grant that authorized the run.

That check is correct and is not loosened here. An authorization is content-addressed over the
exact corpus hash, so a generated case is by construction outside every grant that existed before
it. The missing piece was never a weaker check — it was a governed way to mint a *new* corpus
identity and take a *new* grant for it. That is what this is.

## What is implemented

| Stage | Module | State |
|---|---|---|
| 1 — curate | `agents/red_team/curation.py` | implemented, 16 tests |
| 2 — human review gate | `agents/red_team/review_gate.py` | implemented, 16 tests |
| 3 — new hash + fresh authorization | `campaign/generated_profile.py` | implemented, 16 tests |
| 4 — dispatch through the Policy Gateway | — | **not wired** — stacks on 0022 |
| 5 — evaluate with the oracle/canary Judge | existing | unchanged, not reached by generated cases |

The generator itself (`TracedHostedRedTeamProvider.generate_traced`, qwen, `target_scope:none`)
already existed and is unmodified. It never touches the target and still does not.

### Stage 1 — curate

`curate()` is a total, deterministic, network-free function of (batch, base corpus). Every input
candidate becomes either a `CuratedCandidate` or a typed `CandidateRejection`; the two always
account for the whole batch. Order-independent: the same batch in any order produces the same
bundle digest, which is what makes an approval reproducible.

Pipeline: normalize → materialize + validate against `attack-case.v1.json` → structurally minimize
→ dedupe (within batch and against the base corpus) → novelty-score → content-address.

**The trust boundary is the point.** The untrusted generator authors `input_sequence` and nothing
else. Three rules apply to every other field:

- **inherited** from a reviewed authored template of the same category — `authorization_posture`,
  `expected_typed_failure`, `fixture_provenance`, `owasp`, the target surface;
- **model-authored** — `input_sequence` alone;
- **neutralized** — `oracle_expectation` (forced to `kind: "none"`), `expected_evidence`,
  `severity`, `exploitability`, `ground_truth_refs`.

Neutralization is not cosmetic. A generated case inheriting the template's `synthetic_canary_match`
oracle would assert a deterministic canary hit its own turns may never trip, **and would still pass
schema validation**. `ground_truth_refs` is set to a deliberately non-resolving `GT-M11-GEN-*`
reference, so writing a generated case into the authored corpus fails the corpus validator's
bidirectional case↔label check until a human authors its label — the correct outcome, not an
inconvenience.

Two honest limits:

- **Minimization is structural only.** Repeated turns are collapsed; for volume-sensitive
  categories (`denial_of_service`) collapse is skipped entirely, because "minimizing" a
  token-exhaustion attack by deleting its repeats would destroy it while reporting success.
  Semantic minimization — delete a turn, re-test whether the attack still fires — requires target
  feedback, so it belongs to Tier 2 and is **not** simulated here.
- **Novelty is a lexical measure.** Character-shingle Jaccard distance from the nearest
  same-category authored case, floor 0.20. It catches rewordings. It does not understand semantics,
  and a genuinely novel attack phrased in familiar words could score low.

### Stage 2 — human review gate

`present()` renders the complete reviewer view — every curated candidate **and** every stage-1
rejection, because what curation threw out is the main available signal about whether the generator
is behaving.

`approve()` fails closed, in order: bundle identity → principal well-formedness → self-approval →
decision coverage → per-case content binding → non-empty approval. Refusals pinned by test:

- a bundle mutated after presentation cannot be approved (digest mismatch);
- the generating principal cannot approve its own output (two-person invariant);
- approval by omission is refused — every candidate needs an explicit decision;
- a decision cannot be transplanted onto different content (each names its own `case_sha256`);
- approving nothing is a valid review outcome that authorizes nothing.

Emitted `ReviewRecord`s use the exact provenance shape `campaign.corpus.load_live_100_corpus`
already validates, with `source_kind: "hosted_red_team"` — feeding the existing reviewed-workload
authority rather than inventing a second, weaker notion of "approved".

**An approval is not a grant.** It is the human authorization *decision*. A grant is scoped to an
exact target, host, caps and corpus hash, and minting one is stage 3. Both are required; neither
substitutes for the other.

### Stage 3 — new corpus hash + fresh authorization

`build_generated_corpus()` produces a `GeneratedCorpusProfile` — deliberately parallel to the
existing `ReviewedToolCorpusProfile`. It re-derives every approved case's content hash rather than
trusting the field, so a case mutated between approval and binding is refused. Its `content_hash`
is the standard platform `corpus_sha256` over its own attempts, so it is directly comparable to,
and provably distinct from, the base digest.

`require_fresh_authorization()` refuses, in order: a scope not carrying this profile's corpus hash;
a scope still carrying the **base** corpus hash (checked explicitly, so it cannot be reached by
coincidence); a corpus-id mismatch; a spent run nonce.

`prepare_generated_dispatch()` runs every governed precondition and returns a plan. It is the
complete stage-3 exit.

## What is NOT built

- **Stage 4 — dispatch.** Not wired. It reuses the 0022 governed four-role execution path
  (PR #50, landing on `b0e641c`), which is not merged at this base. `prepare_generated_dispatch()`
  deliberately stops after the gates rather than no-op'ing, because a silent no-op would look
  exactly like a successful dispatch.
- **Tier 2 — the multi-round feedback loop.** **Next, not done.** A round's verdicts do not yet
  steer the next round's generation, and semantic (delta-debugging) minimization is part of that
  work because it needs target feedback.
- **No live run, no verdict, no confirmed exploit** from any generated case.

## Coordination notes

- **No migration.** Stages 1–3 are pure and content-addressed, following the existing
  `tool_profile.py` / `corpus.py` precedent, so no new Alembic revision is claimed and there is no
  numbering collision to reconcile. Stage 4's persistence will ride whatever 0022 provides.
- **No re-export from `agents/red_team/__init__.py`.** `campaign` already depends on
  `agents.red_team`; re-exporting would invert the layering. Callers import the submodules.

## Verification

```
ruff check .                 # All checks passed
ruff format --check .        # 713 files already formatted   (ruff 0.16.0, CI's resolved version)
pytest tests/                # 1901 passed, 3 skipped
pytest tests/test_red_team_curation.py \
       tests/test_red_team_review_gate.py \
       tests/test_generated_campaign_authorization.py   # 48 passed
```
