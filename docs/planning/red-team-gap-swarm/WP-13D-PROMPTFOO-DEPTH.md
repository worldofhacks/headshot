# WP-13D — Use Promptfoo red-team plugins and assertions

**Branch:** `rtg/wp13d-promptfoo-depth`

**Model:** capable

**Depends on:** WP-13

**Implements toward (live validation pending):** Promptfoo portion of RT-05

**Implementation writes only**

- `security-tools/promptfoo/**`
- `security-tools/promptfoo/capabilities.v0.121.19.json`
- `src/agentforge/security_tools/adapters/promptfoo.py`

**Test writes only**

- `tests/security_tools/test_promptfoo_depth.py`
- `tests/vectors/security_tools/promptfoo_depth/**`

## Required result

Generate and check in a machine-validated capability inventory, then create a pinned
Promptfoo 0.121.19 profile with allowlisted target-relevant red-team
plugins/presets, multi-turn cases, deterministic assertions, and explicit plugin-to-risk/
category mappings.
Derive the inventory from the actual pinned package in a no-network environment or a
verified native artifact; if neither exists, return `BLOCKED(capability inventory)`.

Keep telemetry, remote generation, remote red-team generation, cache, and cloud sharing
disabled. Use the frozen WP-13 protocol: remote candidate generation can use only the
generation broker and reviewed candidate execution only the target-dispatch broker. It
cannot accept target URLs, credentials, authorization records, or commands, and its native
profile requires external egress denial. Real native-process proof belongs to
WP-16D/WP-13E; this package remains `adapter_profile_validated`.

Import generated cases/results with plugin, strategy, assertion, provider, config, and
artifact lineage. Promptfoo assertions remain advisory.

Tests cover plugins, multi-turn sequences, assertion normalization, remote-disable flags,
provider containment, malformed/oversized output, duplicate cases, hostile fields, process
escape, pinned-version/profile and capability drift, cross-broker confusion, and zero
direct network from the adapter/provider harness.
These are non-evidentiary profile/adapter checks. Only WP-21C may establish Promptfoo
execution or depth with the exact pinned native process, authorized live target/provider
paths, nonzero accepted native records, complete ledger parity, and independent
adjudication.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_promptfoo_depth.py -q
```

No `npx`, installation, or actual Promptfoo execution in this package. WP-13E owns shared
integration; WP-21C owns live execution evidence.
