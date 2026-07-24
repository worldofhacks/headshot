# WP-21D — Execute the live Web, API, browser, and Burp-workflow matrix

**Branch:** `rtg/wp21d-live-web-burp`

**Model:** capable

**Depends on:** approved WP-21A manifest admitting this lane

**May close with approved evidence:** live portions of RT-06 and relevant RT-01/RT-05/RT-07

Read and follow `ROLE-LIVE-EVIDENCE-EXECUTOR.md`. Use only this lane's immutable manifest
entry and exact authorizations.

**Writes only**

- `evals/results/authorized/web-burp/**`
- `docs/evidence/authorized-red-team/web-burp/**`
- `.tdd-swarm/reports/RTG-WP21D-live-web-burp.md`

## Required live matrix

Run applicable workflows through the deployed platform and exact owner-authorized deployed
target:

1. **Target/site map/API:** collect a current live classic/AJAX crawl and owner-provided
   OpenAPI/Postman/GraphQL contract, bind observed operations to exact target surfaces, and
   keep cross-origin or unregistered edges blocked.
2. **Authentication and access control:** use provisioned live test principals and seeded
   synthetic non-PHI object namespaces for unauthenticated, owner, peer, role, cross-role,
   cross-tenant, revoked/expired/rotated, BOLA, BFLA, fixation, logout, and forced-browsing
   cells. Never scan the identity provider or bypass MFA/CAPTCHA.
3. **Workbench/manual analogues:** exercise deployed capture/history, protected-field
   inspector, intercept/drop/forward-as-new-plan, structured Repeater, bounded Intruder
   positions/modes, extraction/minimization, Decoder, literal Comparer, Search, Organizer,
   and reviewed declarative checks. Preserve `governed_analogue`/`partial` labels for
   Proxy/Repeater; do not claim raw Burp MITM, response editing, CA/invisible proxying,
   arbitrary message replay, or Montoya/BApp parity.
4. **ZAP:** run the exact pinned ZAP image/process through WP-16D for the authorized live API,
   authenticated crawl, passive rules, and separately authorized active rule subset. Require
   scanner request/permit/physical-send/ledger parity and exact add-on/rule/profile hashes.
5. **Browser and streaming:** run the exact pinned isolated browser through WP-16D against
   live HTML/Markdown/URL, DOM, clickjacking, WebSocket, and SSE surfaces. Require live
   navigation/subresource/frame/reconnect observations and deny local-network or alternate
   egress.
6. **Sequencer:** acquire fresh tokens from separately authorized live provisioned sessions
   and run the complete bounded statistical battery with extraction/sample-size/confidence
   lineage. Conversation ordering is not Sequencer.
7. **OAST:** only when the owner architecture decision, deployed authorized callback domain,
   certificate, receiver, protocol, and caps are present, demonstrate a genuine per-attempt
   correlated callback. Otherwise retain `BLOCKED_OWNER_ARCHITECTURE` or
   `BLOCKED_LIVE_OAST`.
8. **Reporting:** render evidence-bound technical/executive drafts with live/partial/blocked/
   unsupported states, redaction, claim/evidence parity, and the critical-finding human
   publication gate. Do not publish.

Use fixed reviewed probes and exact surface-compatible requests only. Never use local
fixtures, a local/fake target, loopback browser page, in-process OAST receiver, saved ZAP
output, simulated principal, or cassette as evidence. A missing pinned process/image,
surface, authorization, callback domain, or test principal is blocked.

Run independent cleanup verification for authorized live state changes. Return the Live
Evidence Executor status contract with per-workflow evidence hashes, scanner/browser/OAST
lineage, request/frame/reconnect counts, cost, and blockers.
