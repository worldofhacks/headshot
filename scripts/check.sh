#!/usr/bin/env bash
# Local validation gate (P8): lint + format-check + tests + secret scan.
# Run with the project venv active:  source .venv/bin/activate && bash scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ruff check =="
ruff check .

echo "== ruff format --check =="
ruff format --check .

echo "== pytest =="
pytest

echo "== secret scan =="
bash scripts/secret_scan.sh

echo "OK — local validation gate passed."
