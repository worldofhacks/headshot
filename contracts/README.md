# Published inter-agent contracts

The reviewer-facing v1 JSON Schemas are in [`v1/`](v1/), as required by the
AgentForge PRD.

`src/agentforge/contracts/v1/` is the canonical authoring and runtime source.
The root files are a byte-for-byte publication, not a second contract authority.
The contract test suite checks the registry, canonical package directory, and
published directory as one exact set and rejects any byte drift.

After changing a canonical schema, refresh and verify the publication:

```sh
python scripts/sync_contracts.py --write
python scripts/sync_contracts.py
pytest tests/contract
```
