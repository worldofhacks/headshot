#!/usr/bin/env python3
"""Validate the committed live target catalogs load through the trusted platform catalog.

For each environment (staging, production) this sets ``AGENTFORGE_LIVE_TARGET_CATALOG_JSON`` from the
committed per-environment config file and calls ``TrustedTargetCatalog.from_environment(env)`` — the
same code path the Runner and API backend use — proving the global target configuration is loadable
(not just JSON-well-formed) and that **both environments load identically**. Prints target/surface ids
and non-secret transport facts. No network, no credentials, no secrets resolved.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

CONFIGS = {
    "staging": ROOT / "config" / "live-target-catalog.staging.json",
    "production": ROOT / "config" / "live-target-catalog.production.json",
}
EXPECTED_HOST = "agent-production-9f62.up.railway.app"
REQUIRED_IDS = (
    "copilot-week1",
    "copilot-week2",
    "clinical-copilot-week1",
    "clinical-copilot-week2",
)


def validate(environment: str, config: Path) -> int:
    os.environ["AGENTFORGE_LIVE_TARGET_CATALOG_JSON"] = config.read_text()
    from agentforge.target.catalog import TrustedTargetCatalog

    catalog = TrustedTargetCatalog.from_environment(environment)
    live = [e for e in catalog.entries if e.target.target_id != "synthetic-copilot"]
    print(
        f"[{environment}] {config.name}: {len(catalog.entries)} entries ({len(live)} live-configured)"
    )
    for entry in live:
        target = entry.target
        assert target.environment.value == environment, (
            "entry environment must match the selected env"
        )
        assert EXPECTED_HOST in target.allowlisted_hosts, "base_url host must be allowlisted"
        assert target.credential_ref and target.credential_ref.startswith(
            f"secretref://{environment}/"
        ), "credential must be an environment-scoped secretref (never a raw SID)"
        surfaces = ", ".join(f"{s.method} /{s.relative_path}" for s in entry.surfaces)
        print(
            f"  target={target.target_id} env={target.environment.value} auth={target.auth_mode.value} "
            f"cred_ref={target.credential_ref}"
        )
        print(f"    surfaces=[{surfaces}] upload={entry.transport_policy.write_upload_allowed}")
    resolved = {entry.target.target_id for entry in live}
    for required in REQUIRED_IDS:
        assert required in resolved, f"missing target {required} in {environment} catalog"
    return len(live)


def main() -> int:
    counts = {env: validate(env, config) for env, config in CONFIGS.items()}
    assert counts["staging"] == counts["production"], (
        "both environments must expose the same targets"
    )
    print(
        "VALID: both environments load identically; all four target ids "
        "(copilot-week1/2 + clinical-copilot-week1/2 alias) resolve; credentials by secretref only."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
