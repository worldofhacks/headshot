#!/usr/bin/env bash
# Local validation gate (P8): lint + format-check + tests + secret scan.
# Run with the project venv active:  source .venv/bin/activate && bash scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ruff check =="
ruff check .

echo "== ruff format --check =="
ruff format --check .

echo "== eval corpus schema + duplicate validation =="
PYTHONPATH=src python -m agentforge.evals validate-corpus evals
PYTHONPATH=src python -m agentforge.evals detect-duplicate-sequence evals/seeds

echo "== pytest =="
pytest

echo "== secret scan =="
bash scripts/secret_scan.sh

echo "OK — local validation gate passed."
