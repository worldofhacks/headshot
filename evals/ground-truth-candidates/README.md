# Ground-truth candidates (pending human attestation)

Candidate ground-truth labels **not yet human-attested** and deliberately OUTSIDE
`evals/ground-truth/` so the `validate-corpus` slice validator does not treat them as
attested slices. They become attested slices only via the calibration lane (v) after
two-person human attestation, which also re-computes `slice_set_sha256`.
