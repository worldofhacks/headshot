# WP-01 — Persisted gate before every physical dispatch

**Branch:** `rtg/wp01-physical-dispatch-gate`

**Model:** capable

**Depends on:** `<RED_TEAM_GAP_BASE_SHA>`

**Implements toward (live validation pending):** RT-09

Read the common role prompt, this package, `src/agentforge/policy/gateway.py`,
`src/agentforge/campaign/coordinator.py`, `src/agentforge/runner.py`, and the RT-09
finding.

**Implementation writes only**

- `src/agentforge/policy/dispatch_gate.py`
- `src/agentforge/policy/gateway.py`
- `src/agentforge/campaign/coordinator.py`
- `src/agentforge/runner.py`

**Test writes only**

- `tests/test_physical_dispatch_gate.py`
- `tests/test_campaign_coordinator.py`

## Required result

Introduce a narrow immutable `PhysicalDispatchContext` and injected persisted-state gate.
The Policy Gateway must invoke the gate after pacing/backoff and immediately before every
physical `adapter.send()`: each conversational turn and every retry. Define a two-phase
transport seam: an optional destination prepare step may resolve and pin a destination,
then the persisted permit and final caps run, then only the already-constrained
connect/TLS/write step may occur. No request body or target operation may begin before the
permit.

The Runner callback must reread authoritative approval, exact scope/corpus hashes, abort
state, authorization expiry, attempt identity, and active lease ownership. Browser state,
prompt content, and adapter metadata are never authority. Live composition without the
gate fails closed. No-socket test composition is an implementation precheck only and can
never create dispatch or live-control evidence.

Tests must prove:

1. three turns cause three gate calls;
2. abort after turn one causes exactly one send;
3. abort or lease loss during retry backoff prevents the retry;
4. approval/scope/hash/expiry changes prevent the next send;
5. there is no sleep, credential refresh, DNS lookup, target-driven redirect, or other
   avoidable blocking work between the final gate and constrained send;
6. gate failures use bounded stable codes without DB/DSN/credential/prompt leakage;
7. gate calls do not consume budget; physical send attempts do;
8. legacy atomic/cassette test behavior remains compatible but is permanently barred from
   the deployed executable target catalog and authoritative evidence path.

WP-21B must demonstrate this cadence on the deployed release with actual authorized
physical requests before RT-09 can close.

**Focused verifier**

```bash
python -m pytest tests/test_physical_dispatch_gate.py tests/test_gateway.py tests/test_runner_campaign.py tests/test_campaign_coordinator.py -q
```

**Security focus:** callback substitution, mutable context, missing callback, abort races,
lease races, clock changes, retry bypass, and exception leakage.

**Handoff:** WP-02, WP-03, WP-04, WP-05, WP-08, WP-12, WP-15, WP-17, and WP-19 consume
this final physical-dispatch seam. WP-03 must wire WP-08 revalidation into Runner preflight
and this permit. Do not implement destination resolution, DB roles, or retry classification
here.
