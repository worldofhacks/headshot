# WP-13A — Use Garak beyond one DAN probe

**Branch:** `rtg/wp13a-garak-depth`

**Model:** capable

**Depends on:** WP-13

**Implements toward (live validation pending):** Garak portion of RT-05

**Implementation writes only**

- `security-tools/garak/**`
- `security-tools/garak/capabilities.v0.15.1.json`
- `security-tools/offline/garak_bridge.py`
- `src/agentforge/security_tools/adapters/garak.py`

**Test writes only**

- `tests/security_tools/test_garak_depth.py`
- `tests/vectors/security_tools/garak_depth/**`

## Required result

Build and check in a machine-validated capability inventory for the installed/pinned Garak
0.15.1 package, then build an allowlisted profile covering supported target-relevant
injection/jailbreak, leakage, encoding/obfuscation, misinformation/hallucination, and
resource-amplification families. Validate identifiers against the pinned capability
inventory; unsupported probes/detectors fail typed rather than being invented.
Derive the inventory from the actual pinned package in a no-network environment or a
verified native artifact; if neither exists, return `BLOCKED(capability inventory)`.

Garak receives the frozen WP-13 target-dispatch broker (and the generation broker only for
an explicitly authorized generation step), never a target URL or credential. Configure the
process-deny requirement, but classify this package only `adapter_profile_validated`;
WP-16D/WP-13E own real process-isolation proof.
Preserve probe/detector/generator identities, ordered attempt prompts, native status,
tool/config hashes, and artifact lineage. Imported prompts are untrusted candidates;
detector results are advisory only.

Tests cover pinned-version/profile preflight, capability-inventory drift, multi-record
import, mappings/categories, refusal/errors, byte/record caps, duplicates, hostile fields,
deterministic hashes, and zero direct socket/SDK/target access.
These are adapter/profile containment tests, not native-process egress evidence.
They cannot establish Garak execution or depth. Only WP-21C may do so by running the exact
pinned native Garak process through the deployed broker/egress path against the authorized
deployed target and producing accepted, independently adjudicated live records.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_garak_depth.py -q
```

Do not edit shared `native.py`, `candidates.py`, `catalog.py`, `corpus.py`, or
`scripts/run_offline_llm_tools.sh`; WP-13E owns integration.
