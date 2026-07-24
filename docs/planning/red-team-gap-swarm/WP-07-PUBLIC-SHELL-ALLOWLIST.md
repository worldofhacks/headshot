# WP-07 — Enumerate the public authentication shell

**Branch:** `rtg/wp07-public-shell-allowlist`

**Model:** capable

**Depends on:** `<RED_TEAM_GAP_BASE_SHA>`

**Implements toward (live validation pending):** part of RT-14

Read the React route contract, FastAPI SPA fallback, Clerk authentication flow,
`docs/deployment/RAILWAY.md:94-110`, and RT-14.

**Implementation writes only**

- `src/agentforge/web.py`
- `console/README.md`

**Test writes only**

- `tests/test_public_shell_routes.py`
- `tests/test_web_m1d.py`

## Required result

Replace the catch-all HTML fallback with a default-deny closed allowlist containing only
`/`, exact required Clerk sign-in/callback paths, `/health`, `/ready`, and existing
fingerprinted assets. Do not introduce `/auth/*`, `/sign-in/*`, or another broad wildcard.

Unknown HTML paths, protected console deep links, API/event/WebSocket/metrics/queue/admin
paths, source maps, dotfiles, traversal, encoded slash, double slash, missing assets,
unexpected methods, and content-negotiation tricks must not receive `index.html`.

Preserve security/cache headers. If protected deep-link refresh cannot be supported without
a backend session bridge, fail closed with 404 and document it rather than making the shell
public.

`tests/test_web_m1d.py` currently treats `/findings/*` and `/targets/*` as public SPA-shell
routes. Replace those obsolete assertions with explicit 404/no-index tests; this is a
security-contract correction, not permission to weaken unrelated Web assertions.

**Focused verifier**

```bash
python -m pytest tests/test_public_shell_routes.py tests/test_web_m1d.py tests/auth/test_m1d_api.py -q
```

**Security focus:** Starlette normalization, alternate encodings, HEAD/OPTIONS confusion,
asset traversal, source maps, and accidental public protected routes.

**Handoff:** WP-18A/B may not expose OAST or browser endpoints through this allowlist. Any new
public callback route requires a separate owner architecture decision. WP-20B/WP-20C
reconcile the final route list into backend/console behavior and documentation.
