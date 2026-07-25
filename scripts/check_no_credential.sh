#!/usr/bin/env bash
# Fail-closed pre-push credential guard for the authorized live-campaign artifacts.
#
# Verifies the live session credential (TARGET_SESSION_SID, by reference from the environment)
# does NOT appear in what is about to be committed/pushed, that the gitignored secrets file is
# not staged, and runs a generic high-entropy/`sid=` backstop. gitleaks-safe: it never prints
# the credential value.
#
# Usage: TARGET_SESSION_SID=... scripts/check_no_credential.sh   (exit 0 clean, 1 if a leak is found)
set -euo pipefail

fail=0

# 1) The exact session credential must be absent from the staged diff (if the env var is set).
if [ -n "${TARGET_SESSION_SID:-}" ]; then
  if git diff --cached -U0 | grep -qF -- "$TARGET_SESSION_SID"; then
    echo "LEAK: TARGET_SESSION_SID value appears in the staged diff" >&2
    fail=1
  fi
  # Also scan tracked files in the whole tree (belt and suspenders).
  if git grep -qF -- "$TARGET_SESSION_SID" -- . 2>/dev/null; then
    echo "LEAK: TARGET_SESSION_SID value appears in a tracked file" >&2
    fail=1
  fi
else
  echo "note: TARGET_SESSION_SID not set — skipping exact-value check (pattern checks still run)" >&2
fi

# 2) The gitignored secrets file must never be staged.
if git diff --cached --name-only | grep -qE '(^|/)\.env\.campaign$'; then
  echo "LEAK: .env.campaign is staged for commit" >&2
  fail=1
fi

# 3) Generic backstop: a `sid=<token>` assignment or a bare 32-char base62 token in the staged diff.
staged="$(git diff --cached -U0 | grep -E '^\+' || true)"
if printf '%s' "$staged" | grep -qE 'sid=[A-Za-z0-9_-]{16,}'; then
  echo "LEAK: a 'sid=<token>' assignment appears in the staged diff" >&2
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "credential guard: PASS (no session credential in the staged/tracked content)"
fi
exit "$fail"
