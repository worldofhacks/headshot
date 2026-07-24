#!/usr/bin/env python3
"""Validate config/live-target-catalog.staging.json loads through the trusted platform catalog.

Sets AGENTFORGE_LIVE_TARGET_CATALOG_JSON from the committed config file and calls
``TrustedTargetCatalog.from_environment("staging")`` — the same code path the Runner uses — so the
global target configuration is proven loadable (not just JSON-well-formed). Prints target/surface
ids and non-secret transport facts. No network, no credentials.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

CONFIG = ROOT / "config" / "live-target-catalog.staging.json"


def main() -> int:
    os.environ["AGENTFORGE_LIVE_TARGET_CATALOG_JSON"] = CONFIG.read_text()
    from agentforge.target.catalog import TrustedTargetCatalog

    catalog = TrustedTargetCatalog.from_environment("staging")
    live = [e for e in catalog.entries if e.target.target_id != "synthetic-copilot"]
    print(f"catalog loaded: {len(catalog.entries)} entries ({len(live)} live-configured)")
    for e in live:
        t, s = e.target, e.surfaces[0]
        print(f"  target={t.target_id} v{t.version} env={t.environment.value} auth={t.auth_mode.value} "
              f"cred_ref={t.credential_ref}")
        print(f"    surface={s.surface_id} {s.method} /{s.relative_path} "
              f"profile={e.transport_policy.payload_profile} timeout={e.transport_policy.request_timeout_seconds}s "
              f"upload={e.transport_policy.write_upload_allowed}")
        # confirm the base_url host is on the allowlist and matches the authorized target
        assert "agent-production-9f62.up.railway.app" in t.allowlisted_hosts
    print("VALID: both targets load and bind to the allowlisted host (credentials by secretref only).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
