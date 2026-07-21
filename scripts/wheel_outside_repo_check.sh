#!/usr/bin/env bash
# Packaging gate: prove the built wheel resolves its schemas WITHOUT a repo checkout.
#
# The seven inter-agent contract schemas (agentforge/contracts/v1/*.json) and the three
# eval-authoring schemas (agentforge/evals/schemas/*.json) now ship INSIDE the package and are
# resolved via importlib.resources. A wheel installed outside any repo checkout must therefore be
# able to validate a corpus using only the schemas it carries. This script builds the wheel,
# installs ONLY it (+ jsonschema) into a fresh venv in a temp dir OUTSIDE the repo, copies just the
# corpus DATA (never the schemas), and runs the installed console from a CWD outside the repo.
#
# Run with the project venv active:  bash scripts/wheel_outside_repo_check.sh
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/agentforge-wheel.XXXXXX")"
trap 'rm -rf "$work"' EXIT

echo "== build wheel =="
python -m pip wheel "$repo_root" --no-deps -w "$work/wheelhouse"
wheel="$(ls "$work"/wheelhouse/agentforge-*.whl)"
echo "wheel: $(basename "$wheel")"

echo "== assert schemas physically ship in the wheel =="
names="$(python - "$wheel" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    print("\n".join(z.namelist()))
PY
)"
required=(
  "agentforge/contracts/v1/campaign_directive.json"
  "agentforge/contracts/v1/attack_attempt.json"
  "agentforge/contracts/v1/attempt_result.json"
  "agentforge/contracts/v1/evidence_envelope.json"
  "agentforge/contracts/v1/verdict.json"
  "agentforge/contracts/v1/regression_admission.json"
  "agentforge/contracts/v1/errors.json"
  "agentforge/evals/schemas/attack-case.v1.json"
  "agentforge/evals/schemas/ground-truth-slice.v1.json"
  "agentforge/evals/schemas/synthetic-fixture.v1.json"
)
for entry in "${required[@]}"; do
  if ! grep -qxF "$entry" <<<"$names"; then
    echo "MISSING from wheel: $entry" >&2
    exit 1
  fi
done
echo "all 10 schemas present in the wheel"

echo "== fresh venv OUTSIDE the repo, install ONLY the wheel + jsonschema =="
python -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --quiet --upgrade pip
"$work/venv/bin/python" -m pip install --quiet "$wheel" "jsonschema>=4"

echo "== copy ONLY corpus DATA (schemas ride in the wheel, never copied) =="
mkdir -p "$work/corpus"
cp -R "$repo_root/evals/seeds" "$work/corpus/seeds"
cp -R "$repo_root/evals/ground-truth" "$work/corpus/ground-truth"
cp -R "$repo_root/evals/fixtures" "$work/corpus/fixtures"

echo "== run installed console from a CWD OUTSIDE the repo =="
( cd "$work" && "$work/venv/bin/python" -m agentforge.evals validate-corpus "$work/corpus" )
( cd "$work" && "$work/venv/bin/python" -m agentforge.evals detect-duplicate-sequence "$work/corpus/seeds" )

echo "OK — wheel resolves packaged schemas with no repo checkout on disk."
