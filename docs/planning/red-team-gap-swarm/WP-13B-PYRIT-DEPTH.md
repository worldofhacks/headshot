# WP-13B — Use PyRIT multi-turn orchestration and transforms

**Branch:** `rtg/wp13b-pyrit-depth`

**Model:** capable

**Depends on:** WP-13

**Implements toward (live validation pending):** PyRIT portion of RT-05

**Implementation writes only**

- `security-tools/pyrit/**`
- `security-tools/pyrit/capabilities.v0.14.0.json`
- `security-tools/offline/pyrit_bridge.py`
- `src/agentforge/security_tools/adapters/pyrit.py`

**Test writes only**

- `tests/security_tools/test_pyrit_depth.py`
- `tests/vectors/security_tools/pyrit_depth/**`

## Required result

Generate and check in a machine-validated inventory for pinned PyRIT 0.14.0. Support
bounded Crescendo, TAP, Skeleton Key, response-driven
multi-turn refinement, and composite converter chains only where the pinned package
actually supports them.
Derive the inventory from the actual pinned package in a no-network environment or a
verified native artifact; if neither exists, return `BLOCKED(capability inventory)`.

Every attacker-model interaction uses the WP-13 generation broker; every target turn uses
the separate target-dispatch broker. Persist orchestrator,
converter, scorer, configuration, artifact, ordered-turn, parent, and result identities.
Scorers remain advisory and cannot authorize traffic, issue a Judge verdict, change
severity, publish, or mark safety.

Tests cover session isolation, turn/depth/call/token caps, composite transform lineage,
fake-broker refinement, refusal/timeout/malformed result, memory cleanup, hostile scorer
containment, pinned-version/profile and capability drift, deterministic import,
cross-broker authority denial, configured process-deny flags, and zero direct network from
the adapter harness. Do not claim native-process isolation before WP-16D/WP-13E.
These are non-evidentiary adapter checks. Only WP-21C may establish PyRIT execution or depth
with the exact pinned native process, live authorized target turns, genuine separately
authorized generation calls, complete ledger parity, and independent adjudication.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_pyrit_depth.py -q
```

Do not edit shared integration files; WP-13E owns them.
