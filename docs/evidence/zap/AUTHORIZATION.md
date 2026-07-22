# Scan authorization

SCAN AUTHORIZATION (passive OWASP ZAP baseline)
- Authorized by: target owner (explicit in-session request for security testing of their target)
- Target (exact host, allowlisted): agent-production-9f62.up.railway.app
- Mode: PASSIVE baseline only (zap-baseline.py) — NO active scanning, NO attack injection
- Auth: UNAUTHENTICATED public surface only — no SMART session injected, no patient data reached
- Scope: exact target host only; off-origin redirects (Clerk / OpenEMR OAuth) NOT scanned
- Caps: spider depth<=5, <=10 children, <=2 min spider, <=5 min total
- Data: target attested synthetic/Synthea only, no real PHI
