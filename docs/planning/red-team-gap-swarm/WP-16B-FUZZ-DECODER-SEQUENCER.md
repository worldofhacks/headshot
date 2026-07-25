# WP-16B — Intruder-style fuzzing, Decoder, minimization, and Sequencer

**Branch:** `rtg/wp16b-fuzz-decoder-sequencer`

**Model:** capable

**Depends on:** WP-16A, WP-11

**Implements toward (live validation pending):** remaining manual-tool portion of RT-06

**Implementation writes only**

- `src/agentforge/security_tools/payload_positions.py`
- `src/agentforge/security_tools/fuzzing.py`
- `src/agentforge/security_tools/payload_transforms.py`
- `src/agentforge/security_tools/fuzz_minimization.py`
- `src/agentforge/security_tools/decoder.py`
- `src/agentforge/security_tools/token_analysis.py`
- `src/agentforge/contracts/v1/fuzz_plan.json`
- `src/agentforge/contracts/v1/fuzz_observation.json`
- `src/agentforge/contracts/v1/minimized_case.json`
- `src/agentforge/contracts/v1/token_sample_plan.json`

**Test writes only**

- `tests/security_tools/test_fuzzing.py`
- `tests/security_tools/test_fuzz_minimization.py`
- `tests/security_tools/test_decoder.py`
- `tests/security_tools/test_token_analysis.py`

## Required result

Support explicitly selected typed positions and deterministic equivalents of Sniper,
Battering Ram, Pitchfork, and Cluster Bomb. Calculate exact maximum physical requests,
bytes, timeout, rate, cost provenance, concurrency, and Cartesian size before plan
creation. Reject over-cap plans; never silently truncate into another test.

Implement bounded deterministic transforms: URL, HTML, JSON, Base64, hex, binary, gzip,
Unicode normalization/confusables, case/whitespace splitting, hashing, JWT structure
inspection without key guessing, and allowlisted PyRIT converter chains. Preserve complete
lineage. No arbitrary plugin, expression, shell, user regex, decompression bomb, or secret.

Extraction supports bounded literals, headers, statuses, JSON pointers, and pre-reviewed
fixed patterns. Extracted values remain hostile observations.

Minimization uses delta debugging only against a trusted deterministic WP-11 oracle. Every
target-assisted trial is separately counted and authorization-bound; similarity/model/tool
scores cannot prove preservation.

Implement actual Burp-style Sequencer semantics: bounded statistical analysis of approved
synthetic-session token samples with clear sample-size/confidence limits. Define an exact
sample-acquisition plan bound to principal/session/surface, extraction rule, authorization,
sample/call/time/rate caps, expiry, and fresh WP-01 permits; WP-21D is the only package that
may execute it on the live target. Analyze per-position and aggregate
alphabet/bit/byte frequency,
entropy estimates, collision rate, runs, serial correlation, transition bias, and
compression, with multiple-test/confidence caveats. It is advisory, never an authentication
verdict. Conversation ordering must not be called Sequencer, and the feature remains
`partial` until genuine authorized sample evidence exists.

A minimized candidate is never directly reusable. It must enter WP-15 as a proposed bundle,
receive independent review, join a new corpus hash, and receive fresh target authorization.

Tests cover mode expansion, cap rejection before calls, structure-preserving substitution,
Unicode/binary/compression limits, extraction non-authority, abort/rate sharing,
flaky/missing-oracle minimization, transform lineage, weak/strong synthetic tokens, small
sample handling, biased/correlated/colliding samples, multiple-test labeling, acquisition
scope drift, and deterministic output.

Local token vectors validate the statistics only. Sequencer remains
`blocked_live_sample_evidence` until WP-21D acquires fresh samples from provisioned sessions
on the exact deployed target and independently approves their complete lineage.

Direct-validate new schemas in this package; WP-19B owns final registry/package parity.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_fuzzing.py tests/security_tools/test_fuzz_minimization.py tests/security_tools/test_decoder.py tests/security_tools/test_token_analysis.py -q
```

**Handoff:** WP-17 uses position manifests; WP-20A dispatches plans and WP-20C corrects
workbench labels.
