# WP-14 — Full OWASP LLM and Agentic corpus

**Branch:** `rtg/wp14-full-spectrum-corpus`

**Model:** capable

**Depends on:** WP-11, WP-12

**Implements toward (live validation pending):** RT-03

Read the canonical PRD, current schemas/seeds/ground truth, WP-11 observation vocabulary,
WP-12 surface capabilities, official OWASP LLM 2025 and Agentic 2026 taxonomies, and RT-03.
Preserve the nine-case M11 corpus; add a versioned successor.

**Implementation writes only**

- `src/agentforge/evals/taxonomy.py`
- `src/agentforge/evals/full_spectrum.py`
- `src/agentforge/evals/validation.py`
- `src/agentforge/evals/__main__.py`
- `src/agentforge/evals/__init__.py`
- `src/agentforge/evals/schemas/attack-case.v2.json`
- `src/agentforge/evals/schemas/corpus-manifest.v1.json`
- `src/agentforge/evals/schemas/applicability-record.v1.json`
- `src/agentforge/evals/schemas/applicability-review.v1.json`
- `evals/corpora/full-spectrum-v2/**`
- `docs/evidence/FULL_SPECTRUM_COVERAGE_MATRIX.md`

**Test writes only**

- `tests/evals/test_taxonomy_registry.py`
- `tests/evals/test_full_spectrum_corpus.py`
- `tests/evals/test_full_spectrum_ground_truth.py`
- `tests/vectors/evals/full-spectrum-ground-truth-candidates/**`
- `evals/ground-truth/full-spectrum/cases/**`
- `evals/ground-truth/full-spectrum/candidate-manifest.json`

## Required result

Create an exact registry for OWASP Web 2021, OWASP LLM 2025 LLM01–LLM10, and OWASP
Agentic 2026 ASI01–ASI10:

1. Agent Goal Hijack;
2. Tool Misuse & Exploitation;
3. Identity & Privilege Abuse;
4. Agentic Supply Chain Vulnerabilities;
5. Unexpected Code Execution;
6. Memory & Context Poisoning;
7. Insecure Inter-Agent Communication;
8. Cascading Failures;
9. Human-Agent Trust Exploitation;
10. Rogue Agents.

Populate all six PRD categories. Build cases from a surface × principal × state × attack ×
oracle matrix. Every applicable LLM and Agentic risk needs boundary, invariant, and
regression cases or a separately reviewed applicability record. A proposed N/A binds exact
taxonomy/risk version, target/platform subject, surface/version, corpus hash, reason/
evidence, author, distinct authorized Headshot human reviewer, decision/hash/time,
expiry/review trigger, and replacement requirement when capability appears. Missing
surface support is `blocked_missing_surface`, not automatically N/A. Many tags on one chat
prompt do not satisfy breadth.

Every case binds one primary risk, bounded secondary mappings, target/platform subject,
exact WP-12 target or governed internal platform capability, principal/tenant/patient/
session state, B/I/R classification,
positive/negative controls, safe behavior, WP-11 observation requirements, execution state
(`authored`, `blocked_missing_surface`, `executable`), synthetic provenance, and regression
eligibility. Authored corpus files may never self-assert `executed`; execution is projected
only from WP-10's authoritative attempt/evidence ledger.

Corpus cases are non-PHI attack inputs, not target-response fixtures and not execution
evidence. Only WP-21C/WP-21D attempts against the exact deployed target may advance them
beyond `executable`.

Required depth includes true ingestion/RAG injection, transformed leakage, supply chain,
poisoning lifecycle, real sinks, excessive agency, partial prompt inference, vector/
metadata isolation, synthetic misinformation, consumption attacks, memory poisoning,
inter-agent injection, confused deputy, cascading failure, human trust, and rogue-agent
containment.

Manifest membership—not a hard-coded count—determines corpus hash. Reject duplicate and
Unicode-confusable inputs, unsupported oracle claims, incorrect taxonomy names/versions,
missing ground truth, any real PHI/production record content, self-asserted execution, or live-execution
claims without evidence. The loader/CLI must validate canonical LLM and ASI identifiers,
names, versions, applicability records, surface compatibility, and required-oracle policy
hashes rather than accepting arbitrary tags. Test agents may author unlabeled candidate
cases only; human ground-truth labels/reviews are read-only and validated through
`ROLE-GROUND-TRUTH-REVIEWER.md`. A proposed N/A is not excluded from required coverage
until `ROLE-APPLICABILITY-REVIEWER.md` validates its existing human approval and exact
manifest hash; otherwise it remains a visible blocker.

**Focused verifier**

```bash
python -m pytest tests/evals/test_taxonomy_registry.py tests/evals/test_full_spectrum_corpus.py tests/evals/test_full_spectrum_ground_truth.py -q
PYTHONPATH=src python -m agentforge.evals validate-corpus evals/corpora/full-spectrum-v2
```

**Handoff:** WP-19 selects regression cases; WP-20A loads the manifest; WP-21C may execute
only the exact reviewed manifest hash. The corpus cannot integrate human labels or an N/A
exclusion before both independent reviewer gates.
