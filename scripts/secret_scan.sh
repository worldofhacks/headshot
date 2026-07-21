#!/usr/bin/env bash
# Lightweight secret-pattern scan over tracked + new files (P8/P11 precursor).
# A fast local guard, NOT a replacement for gitleaks in the P11 bootstrap (which runs before
# the first push). Portable to macOS Bash 3.2 (no mapfile). Fails if a likely secret is found.
set -euo pipefail
cd "$(dirname "$0")/.."

# Private keys, AWS keys, OpenAI/Slack-style tokens, and generic long secret assignments.
PATTERNS='-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|(api[_-]?key|secret|token|password)["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9/+_-]{16,}'

found=0
count=0
while IFS= read -r f; do
  case "$f" in
    .venv/*|.git/*) continue ;;
    *.png|*.jpg|*.jpeg|*.gif|*.pdf|*.excalidraw|*.svg|*.lock) continue ;;
  esac
  [ -f "$f" ] || continue
  count=$((count + 1))
  if grep -InE "$PATTERNS" "$f" >/dev/null 2>&1; then
    echo "POTENTIAL SECRET in $f:"
    grep -InE "$PATTERNS" "$f"
    found=1
  fi
done < <(git ls-files --cached --others --exclude-standard)

if [ "$found" -eq 1 ]; then
  exit 1
fi
echo "secret scan clean ($count files)"
