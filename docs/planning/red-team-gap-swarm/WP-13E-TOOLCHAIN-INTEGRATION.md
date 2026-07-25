# WP-13E — Integrate the full existing LLM toolchain

**Branch:** `rtg/wp13e-toolchain-integration`

**Model:** capable

**Depends on:** WP-13, WP-13A, WP-13B, WP-13C, WP-13D, WP-10, WP-14, WP-16D

**Implements toward (live validation pending):** remaining RT-05

**Implementation writes only**

- `src/agentforge/security_tools/native.py`
- `src/agentforge/security_tools/candidates.py`
- `src/agentforge/security_tools/catalog.py`
- `src/agentforge/security_tools/repository.py`
- `security-tools/profiles/full-spectrum.v1.json`
- `security-tools/toolchain.lock.json`
- `scripts/run_offline_llm_tools.sh`
- `docs/security/LLM_TOOLCHAIN.md`

**Test writes only**

- `tests/security_tools/test_full_tool_matrix.py`
- `tests/security_tools/test_tool_broker_integration.py`

## Required result

Integrate all four adapters behind the frozen, separate WP-13 generation and target-
dispatch broker protocols. Tools never receive a target credential or alternate network
path. Every physical target request must ultimately use WP-01/WP-03 under exact tool/
version/config/target/surface/corpus/cap authorization, and attacker-model generation has
its distinct `target_scope:none` ledger. Native processes use WP-16D; adapter-level broker
injection alone is not process-isolation evidence.

Replace fixed bundle filename/count policy with a proposed-bundle manifest binding the
checked-in capability inventories, tool versions, profiles, native artifact hashes,
candidate hashes, taxonomy/surface mappings, required-oracle policy refs, and lineage.
This package must not contain a reviewer decision or resulting corpus hash. Native
artifacts are immutable; normalized candidates remain `proposed` until WP-15 independent
human review creates a fresh corpus. Tool findings remain advisory.

Derive catalog states independently:

- adapter integrated;
- profile validated;
- artifact imported;
- candidate reviewed;
- authorized execution observed;
- independently adjudicated.

Never call a tool “operational and evidenced” from adapter presence or a simulated artifact.
Local native artifacts and broker tests are also non-evidentiary. `operational` requires
WP-21C to run the genuine pinned process in the deployed private runtime against the exact
authorized deployed target, with process isolation, accepted native records, physical
ledger parity, and independent adjudication.

Tests cover all tools, multi-category candidates, broker/ledger parity, distinct generation
and target authority, cap enforcement, artifact tampering, capability/version/config drift,
pending review, target/corpus mismatch, advisory containment, and truthful zero-candidate
state.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_full_tool_matrix.py tests/security_tools/test_tool_broker_integration.py tests/security_tools -q
```

Do not run/install the native tools or contact a target/model. WP-21C owns authorized live
execution; WP-21 reconciles and independently reviews its evidence.

**Handoff:** WP-15 is the sole owner of bundle review decisions and resulting reviewed
corpus hashes.
