# Hosted prompt registry v1

The four hosted-agent system prompts are now immutable package resources under
`agentforge.agents.prompts`. The v1 manifest binds each exact role, version, resource name, and
SHA-256 of the raw UTF-8 bytes, including the trailing newline.

Runtime consumers must resolve the complete identity through `load_prompt_registry()` or
`prompt_for_identity(role, version, sha256)`. Environment variables, database prompt bodies,
browser-authored text, checkout-relative paths, and role-only lookup are not prompt authority.
Missing, altered, ambiguous, oversized, non-UTF-8, or secret-shaped resources fail closed with a
generic error before provider composition.

The current integration candidate now requires the staged role configuration's prompt SHA-256 to
match this registry before composing the exact system message for a provider send. Every physical
send/retry records the resolved prompt version and digest without persisting prompt text. This is
implemented and locally tested candidate behavior; it is not evidence of a deployed provider call.

Deployment must build and verify a wheel outside the checkout before promotion. Rollback deploys
the preceding reviewed wheel and its matching staged configuration; it must not mix v1
configuration hashes with prompt bytes from another release. Changing any prompt byte requires a
new manifest digest, configuration approval, and migration record rather than an in-place edit.
