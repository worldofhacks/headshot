# WP-13 — Establish separate generation and target-dispatch brokers

**Branch:** `rtg/wp13-tool-broker`

**Model:** capable

**Depends on:** WP-01

**Implements toward (live validation pending):** authority foundation for RT-04 and RT-05

Read the Policy Gateway, physical-dispatch gate, provider transport/configuration,
security-tool process wrapper, authorization contracts, cost accounting, and RT-04/RT-05.

**Implementation writes only**

- `src/agentforge/security_tools/broker.py`
- `src/agentforge/security_tools/broker_protocol.py`
- `src/agentforge/contracts/v1/tool_generation_request.json`
- `src/agentforge/contracts/v1/tool_target_request.json`
- `src/agentforge/contracts/v1/tool_broker_observation.json`
- `security-tools/BROKER_PROTOCOL.md`

**Test writes only**

- `tests/security_tools/test_tool_broker.py`
- `tests/security_tools/test_tool_broker_protocol.py`

## Required result

Define two non-interchangeable, injected capabilities:

1. `AttackerGenerationBroker` accepts only content-addressed synthetic seeds and an exact
   `target_scope:none` generation authorization. It binds provider/model/configuration,
   prompt/policy hashes, call/token/USD/time caps, expiry, and provider accounting. It has
   no target adapter, target credential, target URL, ownership record, or campaign permit.
2. `TargetDispatchBroker` accepts only reviewed candidate/case identities and an exact
   target/surface/corpus campaign authorization. It routes every turn/retry through the
   WP-01 physical permit and exposes no raw URL, credential, provider SDK, or alternate
   client to a tool.

Use distinct request types, credentials, ledgers, counters, idempotency domains, and error
codes. Generation authority must never satisfy target dispatch, and campaign authority
must never pay for attacker-model generation. Broker observations are advisory lineage;
they cannot approve a bundle, decide a Judge verdict, set coverage, or publish.

The protocol requires native tool processes to run with process-level external egress
denied and communicate only over a bounded authenticated local IPC/stdio protocol. This
package proves the contract with a non-evidentiary child-process precheck; WP-16D and
WP-13E implement the real tool-process composition, and WP-21C must prove it in the deployed
runtime before any operational state. Validate protocol version, message
size/depth/count, IDs, sequence, timeouts, cancellation, and content hashes before routing.
Unknown message types, commands, paths, environment access, callback URLs, credential
fields, or authority-bearing payloads fail closed. No secret is returned to the tool.

Tests prove cross-broker type confusion and replay fail, caps are atomic under concurrency,
abort/expiry stops the next turn, tool crashes cannot bypass accounting, hostile output
cannot create authority, and a process with either broker still has zero direct socket/
SDK/target access. Contract schemas are direct-validated here; WP-19B performs final
registry, compatibility, and installed-wheel stewardship.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_tool_broker.py tests/security_tools/test_tool_broker_protocol.py tests/test_physical_dispatch_gate.py -q
```

No provider, model, target, native tool, package installation, or network execution. All
broker/tool states remain `LIVE_EVIDENCE_REQUIRED`.

**Handoff:** WP-13A–D implement only this frozen protocol. WP-13E integrates their proposed
artifacts with WP-16D process isolation; WP-15 reviews candidate bundles; WP-20A connects
target dispatch to WP-03.
