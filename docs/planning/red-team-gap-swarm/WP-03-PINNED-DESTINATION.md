# WP-03 — Pin validated destinations and preserve TLS identity

**Branch:** `rtg/wp03-pinned-destination`

**Model:** capable

**Depends on:** WP-01, WP-08

**Implements toward (live validation pending):** RT-11

Read the target binding, destination validation, OpenEMR adapter, HTTP client construction,
and RT-11.

**Implementation writes only**

- `src/agentforge/target/destination.py`
- `src/agentforge/target/pinned_transport.py`
- `src/agentforge/target/openemr_adapter.py`
- `src/agentforge/runner.py`
- `docs/deployment/RAILWAY.md`

**Test writes only**

- `tests/target/test_pinned_destination.py`
- `tests/target/test_ownership_dispatch_integration.py`

## Required result

Replace validate-then-reresolve with a pinned connection boundary:

1. at Runner preflight, verify the WP-08 record for the exact target/surface/run scope;
2. resolve the exact authorized hostname and port immediately before a new connection;
3. reject the entire answer set if any address violates catalog policy;
4. pin the approved literal address and immutable TLS/Host authority;
5. re-run the fresh WP-01 persisted permit, including WP-08 ownership verification of the
   exact record/hash, after pinning and before any target request body;
6. connect to the pinned literal address without a second hostname lookup;
7. preserve the original authorized hostname for TLS SNI, certificate verification, and
   HTTP Host authority;
8. verify/constrain the peer before request-body transmission;
9. repeat resolution, ownership/permit validation, and pinning for every new connection
   and safe retry;
10. retain redirects disabled and `trust_env=false`.

Keep resolution and transport injectable/lazy so imports and preflight are networkless.
Reject loopback, private, link-local, metadata, multicast, unspecified, reserved,
IPv4-mapped IPv6, mixed public/private answers, invalid IDNA, trailing-dot ambiguity,
userinfo, and unsafe explicit ports. A private staging exception requires exact IP/CIDR/
network references in the signed WP-08 ownership record and the run authorization; a
boolean “private destination class” is never sufficient.

Tests use resolver/connector/client doubles plus a loopback-only, no-external-network TLS
harness to prove real SNI and certificate-name behavior. Demonstrate that a public answer
changing to private cannot redirect the actual connection, and that ownership expiry or
scope drift after resolution causes zero request-body bytes. A URL rewrite to an IP without
correct SNI/certificate verification is not acceptable.

Those are implementation prechecks only. WP-21B must demonstrate resolution/pinning,
certificate/SNI/Host identity, redirect denial, revalidation, and physical-send lineage on
the exact deployed authorized target or owner-provided live validation surface. Missing
safe live behavior remains blocked; a loopback harness cannot close RT-11.

**Focused verifier**

```bash
python -m pytest tests/target/test_pinned_destination.py tests/target/test_ownership_dispatch_integration.py tests/test_openemr_adapter.py tests/test_openemr_adapter_chat.py tests/test_runner_campaign.py -q
```

**Security focus:** SNI mismatch, Host smuggling, IPv6 normalization, pool reuse, proxy
environment, fallback DNS, redirects, and validation after body transmission.

**Handoff:** WP-04 consumes the pinned transport's delivery-stage errors. WP-17 and WP-18A/B
must use this egress boundary rather than a second client.
