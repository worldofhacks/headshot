# WP-13C — Execute meaningful Giskard scenario imports

**Branch:** `rtg/wp13c-giskard-depth`

**Model:** capable

**Depends on:** WP-13

**Implements toward (live validation pending):** Giskard portion of RT-05

**Implementation writes only**

- `security-tools/giskard/**`
- `security-tools/giskard/capabilities.v1.0.0b3.json`
- `security-tools/offline/giskard_bridge.py`
- `src/agentforge/security_tools/adapters/giskard.py`

**Test writes only**

- `tests/security_tools/test_giskard_depth.py`
- `tests/vectors/security_tools/giskard_depth/**`

## Required result

Generate and check in a machine-validated capability inventory for pinned Giskard
1.0.0b3, then import resolved owned-target and RAG scenarios, scenario
interactions, and scan results. Support GOAT/Crescendo/GCG only when present in the pinned
capability inventory. A configured run producing zero explicit candidates is a truthful
typed non-operational result, not success.
Derive the inventory from the actual pinned package in a no-network environment or a
verified native artifact; if neither exists, return `BLOCKED(capability inventory)`.

Target/RAG callables are injected WP-13 target-dispatch broker adapters; any attacker-model
generation uses its separate generation broker. They cannot accept raw URLs, credentials,
unrestricted datasets, or real PHI. Configure process denial, but defer real native-process
isolation implementation to WP-16D/WP-13E. Repository test vectors are non-PHI and
tenant/patient scoped, but are never execution evidence.

Normalize scenario/step/result IDs, tags, ordered turns, tool/config/artifact hashes, and
advisory findings. Giskard labels never become Judge verdicts.

Tests cover multi-step/RAG metadata, zero-candidate failure, unsupported features,
malformed/oversized artifacts, duplicate scenarios, hostile result text, mapping
validation, pinned-version/profile and capability drift, cross-broker confusion, and zero
direct network from the adapter harness; this is not process-isolation evidence.
Only WP-21C may establish Giskard execution or depth with the exact pinned native process,
live owned-target/RAG scenarios on seeded target records, nonzero accepted native records,
complete ledger parity, and independent adjudication.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_giskard_depth.py -q
```

Do not edit shared integration files; WP-13E owns them.
