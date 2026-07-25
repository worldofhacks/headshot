# Submission-artifact finalization

This directory contains **bindable pre-release records**, not evidence placeholders that may be
mistaken for completed proof.

- [`RELEASE_BINDING.md`](RELEASE_BINDING.md) is the atomic checklist for the exact source, image,
  migration, CI, mirror, staging, production, campaign, and manifest identities.
- [`COST_INPUTS.md`](COST_INPUTS.md) names the billing and usage inputs required before any actual
  development or run-cost number is published.
- [`SOCIAL_POST_DRAFT.md`](SOCIAL_POST_DRAFT.md) is an explicitly unpublished draft whose factual
  fields remain blocked on the final run.

Rules:

1. Retain `pending` for any value without an immutable artifact.
2. Bind every published claim to the final SHA and, where applicable, an environment, deployment,
   migration, campaign, and content hash.
3. Do not convert a configuration budget, reservation ceiling, fixture, mock, cassette, estimated
   provider price, or prose summary into measured evidence.
4. Regenerate counts and severities from retained manifests. Mapped is not covered, and
   `INDETERMINATE` is not a safe result.
5. Never place a credential, session value, raw hostile prompt/response, or clinical body here.
