#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON_BIN:-python3}"
python_path="$(command -v "$python_bin")"
if [[ -n "${LLM_TOOL_WORK_DIR:-}" ]]; then
  work_root="$LLM_TOOL_WORK_DIR"
else
  work_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/agentforge-llm-tools.XXXXXX")"
fi
artifact_dir="${LLM_TOOL_ARTIFACT_DIR:-$work_root/artifacts}"
mkdir -p "$work_root" "$artifact_dir"

run_without_ci_credentials() {
  local tool_home="$1"
  local tool_tmp="$2"
  shift 2
  mkdir -p "$tool_home" "$tool_tmp"
  env -i \
    PATH="$PATH" \
    HOME="$tool_home" \
    TMPDIR="$tool_tmp" \
    LANG=C.UTF-8 \
    "$@"
}

"$python_bin" -m venv "$work_root/garak"
"$work_root/garak/bin/pip" install --disable-pip-version-check litellm==1.84.0 garak==0.15.1
run_without_ci_credentials "$work_root/home-garak" "$work_root/tmp-garak" \
  "$work_root/garak/bin/python" security-tools/offline/garak_bridge.py \
  "$artifact_dir/garak.report.jsonl"

"$python_bin" -m venv "$work_root/pyrit"
"$work_root/pyrit/bin/pip" install --disable-pip-version-check pyrit==0.14.0
run_without_ci_credentials "$work_root/home-pyrit" "$work_root/tmp-pyrit" \
  "$work_root/pyrit/bin/python" security-tools/offline/pyrit_bridge.py "$artifact_dir/pyrit.json"

giskard_wheel="$work_root/giskard_scan-1.0.0b3-py3-none-any.whl"
curl -sSfL \
  https://github.com/Giskard-AI/giskard-oss/releases/download/giskard-scan/v1.0.0b3/giskard_scan-1.0.0b3-py3-none-any.whl \
  -o "$giskard_wheel"
"$python_bin" - "$giskard_wheel" <<'PY'
import hashlib
import pathlib
import sys

wheel = pathlib.Path(sys.argv[1])
expected = "38ecd28d91e2f28962b413545b76030db2081ff142aa140dd36f5539a77b0da3"
if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected:
    raise SystemExit("Giskard wheel checksum mismatch")
PY
"$python_bin" -m venv "$work_root/giskard"
"$work_root/giskard/bin/pip" install --disable-pip-version-check "$giskard_wheel"
run_without_ci_credentials "$work_root/home-giskard" "$work_root/tmp-giskard" \
  "$work_root/giskard/bin/python" security-tools/offline/giskard_bridge.py \
  "$artifact_dir/giskard.json"

run_without_ci_credentials "$work_root/home-promptfoo" "$work_root/tmp-promptfoo" \
  env \
  PROMPTFOO_DISABLE_TELEMETRY=1 \
  PROMPTFOO_DISABLE_REMOTE_GENERATION=true \
  PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true \
  "$python_path" -c \
  'import subprocess, sys; subprocess.run(sys.argv[1:], check=True, timeout=120)' \
  npx --yes promptfoo@0.121.19 eval \
  -c security-tools/promptfoo/promptfooconfig.yaml --no-cache \
  --output "$artifact_dir/promptfoo.json"

PYTHONPATH=src "$work_root/giskard/bin/python" \
  security-tools/offline/validate_native_artifacts.py "$artifact_dir"
find "$artifact_dir" -type f -size +10M -print -quit | grep -q . && {
  echo "offline LLM-security artifact exceeded 10 MiB" >&2
  exit 1
}
