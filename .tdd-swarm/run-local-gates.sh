#!/usr/bin/env bash
set -euo pipefail

readonly MAX_RECORDED_OUTPUT=16384

if [[ $# -ne 2 ]]; then
  printf 'usage: %s <ticket-file> <diff-base>\n' "$0" >&2
  exit 2
fi

ticket_file=$1
diff_base=$2
readonly policy_file=".tdd-swarm/coverage-policy.md"
readonly gate_map=".tdd-swarm/gates.md"

fail() {
  printf 'local-gates: %s\n' "$1" >&2
  exit 1
}

[[ -f "$ticket_file" && ! -L "$ticket_file" ]] ||
  fail "ticket is not a regular file: $ticket_file"
[[ -f "$policy_file" && ! -L "$policy_file" ]] ||
  fail "coverage-policy is absent or not a regular file: $policy_file"
[[ -f "$gate_map" && ! -L "$gate_map" ]] ||
  fail "gate map is absent or not a regular file: $gate_map"
[[ -f .tdd-swarm/spec-lint.sh && ! -L .tdd-swarm/spec-lint.sh ]] ||
  fail "spec-lint tool is absent"
[[ -f .tdd-swarm/check-import-cycles.py && ! -L .tdd-swarm/check-import-cycles.py ]] ||
  fail "import-cycle tool is absent"

[[ "$diff_base" =~ ^[0-9a-fA-F]{7,64}$ ]] ||
  fail "diff-base must be a hexadecimal commit id"
base_sha=$(git rev-parse --verify "${diff_base}^{commit}" 2>/dev/null) ||
  fail "invalid diff-base commit: $diff_base"
head_sha=$(git rev-parse --verify "HEAD^{commit}" 2>/dev/null) ||
  fail "cannot resolve HEAD"

ticket_id=$(
  python3 - "$ticket_file" <<'PY'
import re
import sys
from pathlib import Path

repository = Path.cwd().resolve()
ticket = Path(sys.argv[1])
try:
    ticket.resolve(strict=True).relative_to(repository / "tickets")
except (OSError, ValueError):
    print(
        "local-gates: ticket must resolve inside the repository tickets directory",
        file=sys.stderr,
    )
    raise SystemExit(1)
text = ticket.read_text(encoding="utf-8")
frontmatter = re.match(r"\A---\n(.*?)\n---(?:\n|\Z)", text, re.DOTALL)
ids = [] if frontmatter is None else re.findall(
    r"(?m)^id:\s*([A-Za-z0-9-]+)\s*$", frontmatter.group(1)
)
if len(ids) != 1:
    print("local-gates: ticket must declare exactly one safe id", file=sys.stderr)
    raise SystemExit(1)
print(ids[0])
PY
) || exit 1

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/tdd-swarm-gates.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT
policy_values="$temporary_directory/policy.tsv"
gate_values="$temporary_directory/gates.tsv"

if ! python3 - "$policy_file" "$policy_values" <<'PY'
from __future__ import annotations

import re
import sys
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

policy_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
try:
    text = policy_path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as exc:
    print(f"coverage-policy: cannot read policy: {exc}", file=sys.stderr)
    raise SystemExit(1)

fields: dict[str, str] = {}
for number, line in enumerate(text.splitlines(), 1):
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    match = re.fullmatch(r"([a-z][a-z0-9-]*):[ \t]*(.*)", line)
    if match is None:
        print(f"coverage-policy: malformed line {number}", file=sys.stderr)
        raise SystemExit(1)
    key, value = match.groups()
    if key in fields:
        print(f"coverage-policy: duplicate field {key}", file=sys.stderr)
        raise SystemExit(1)
    if "\t" in value:
        print(f"coverage-policy: tab is not allowed in {key}", file=sys.stderr)
        raise SystemExit(1)
    fields[key] = value.strip()

decision = fields.get("decision", "")
allowed: set[str]
if decision == "non-applicable":
    required = {"decision", "reason", "approver", "date", "expiry"}
    allowed = required
    for field in ("reason", "approver", "date", "expiry"):
        if not fields.get(field):
            print(f"coverage-policy: missing {field}", file=sys.stderr)
            raise SystemExit(1)
    try:
        approved_on = date.fromisoformat(fields["date"])
        expires_on = date.fromisoformat(fields["expiry"])
    except ValueError:
        print("coverage-policy: date and expiry must be ISO dates", file=sys.stderr)
        raise SystemExit(1)
    if approved_on > date.today():
        print("coverage-policy: approval date is in the future", file=sys.stderr)
        raise SystemExit(1)
    if expires_on < date.today():
        print(f"coverage-policy: waiver expired on {expires_on}", file=sys.stderr)
        raise SystemExit(1)
elif decision == "executable":
    required = {
        "decision",
        "coverage-command",
        "baseline-base-sha",
        "baseline-percent",
    }
    allowed = required
    for field in ("coverage-command", "baseline-base-sha", "baseline-percent"):
        if not fields.get(field):
            label = "base-SHA" if field == "baseline-base-sha" else field
            print(f"coverage-policy: missing {label}", file=sys.stderr)
            raise SystemExit(1)
    if len(fields["coverage-command"]) > 2048:
        print("coverage-policy: coverage-command is too long", file=sys.stderr)
        raise SystemExit(1)
    try:
        baseline = Decimal(fields["baseline-percent"])
    except InvalidOperation:
        print("coverage-policy: baseline-percent is not numeric", file=sys.stderr)
        raise SystemExit(1)
    if not Decimal("0") <= baseline <= Decimal("100"):
        print("coverage-policy: baseline-percent must be between 0 and 100", file=sys.stderr)
        raise SystemExit(1)
else:
    print("coverage-policy: decision must be executable or non-applicable", file=sys.stderr)
    raise SystemExit(1)

unknown = sorted(set(fields) - allowed)
missing = sorted(required - set(fields))
if unknown:
    print(f"coverage-policy: unknown fields: {', '.join(unknown)}", file=sys.stderr)
    raise SystemExit(1)
if missing:
    print(f"coverage-policy: missing fields: {', '.join(missing)}", file=sys.stderr)
    raise SystemExit(1)

output_path.write_text(
    "".join(f"{key}\t{fields[key]}\n" for key in sorted(fields)),
    encoding="utf-8",
)
PY
then
  exit 1
fi

coverage_decision=
coverage_command=
baseline_base_sha=
baseline_percent=
coverage_reason=
coverage_approver=
coverage_date=
coverage_expiry=
while IFS=$'\t' read -r key value; do
  case "$key" in
    decision) coverage_decision=$value ;;
    coverage-command) coverage_command=$value ;;
    baseline-base-sha) baseline_base_sha=$value ;;
    baseline-percent) baseline_percent=$value ;;
    reason) coverage_reason=$value ;;
    approver) coverage_approver=$value ;;
    date) coverage_date=$value ;;
    expiry) coverage_expiry=$value ;;
  esac
done <"$policy_values"

if [[ "$coverage_decision" == "executable" ]]; then
  [[ "$baseline_base_sha" =~ ^[0-9a-fA-F]{7,64}$ ]] ||
    fail "coverage-policy baseline base-SHA must be a hexadecimal commit id"
  policy_base_sha=$(git rev-parse --verify "${baseline_base_sha}^{commit}" 2>/dev/null) ||
    fail "coverage-policy baseline base-SHA is not a commit"
  [[ "$policy_base_sha" == "$base_sha" ]] ||
    fail "coverage-policy baseline base-SHA does not match supplied diff-base"
fi

if ! python3 - "$gate_map" "$gate_values" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
output = Path(sys.argv[2])
rows: list[tuple[str, str]] = []
seen: set[str] = set()
in_table = False
for number, line in enumerate(text.splitlines(), 1):
    normalized = line.strip().lower()
    if normalized == "| gate | exact command | current status |":
        in_table = True
        continue
    if not in_table:
        continue
    if not line.strip().startswith("|"):
        if rows:
            break
        continue
    cells = [cell.strip() for cell in line.strip().split("|")[1:-1]]
    if len(cells) != 3:
        print(f"gates: malformed table row {number}", file=sys.stderr)
        raise SystemExit(1)
    gate, command, status = cells
    if set(gate) <= {"-", ":"}:
        continue
    if status != "AVAILABLE":
        continue
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _/-]{0,63}", gate):
        print(f"gates: unsafe gate name on row {number}", file=sys.stderr)
        raise SystemExit(1)
    if not command or len(command) > 2048 or "\t" in command or "`" in command:
        print(f"gates: unsafe exact command on row {number}", file=sys.stderr)
        raise SystemExit(1)
    if gate in seen:
        print(f"gates: duplicate gate {gate}", file=sys.stderr)
        raise SystemExit(1)
    seen.add(gate)
    rows.append((gate, command))

if not rows:
    print("gates: no AVAILABLE executable rows", file=sys.stderr)
    raise SystemExit(1)
output.write_text(
    "".join(f"{gate}\t{command}\n" for gate, command in rows),
    encoding="utf-8",
)
PY
then
  exit 1
fi

run_exact_command() {
  local command=$1
  local output_file=$2
  python3 - "$command" "$output_file" "$MAX_RECORDED_OUTPUT" <<'PY'
from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

command, output_name, limit_text = sys.argv[1:]
try:
    arguments = shlex.split(command, posix=True)
except ValueError as exc:
    print(f"command parse error: {exc}", file=sys.stderr)
    raise SystemExit(126)
if not arguments:
    print("command parse error: empty command", file=sys.stderr)
    raise SystemExit(126)

limit = int(limit_text)
try:
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
except OSError as exc:
    Path(output_name).write_text(f"command start error: {exc}\n", encoding="utf-8")
    raise SystemExit(127)

recorded = bytearray()
assert process.stdout is not None
while chunk := process.stdout.read(65536):
    if len(recorded) < limit:
        recorded.extend(chunk[: limit - len(recorded)])
status = process.wait()
if len(recorded) == limit:
    recorded.extend(b"\n[output truncated at 16384 bytes]\n")
Path(output_name).write_bytes(recorded)
raise SystemExit(status if 0 <= status <= 255 else 1)
PY
}

markdown_cell() {
  python3 - "$1" <<'PY'
import sys

value = sys.argv[1]
value = value.replace("\\", "\\\\").replace("|", "\\|")
value = value.replace("`", "&#96;").replace("\r", "").replace("\n", "<br>")
print(value, end="")
PY
}

policy_hash=$(python3 - "$policy_file" <<'PY'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)

overall_status=0
report_rows="$temporary_directory/report-rows.md"
: >"$report_rows"

record_gate() {
  local gate=$1
  local command=$2
  local status=$3
  local output_file=$4
  local output command_cell gate_cell
  output=$(python3 - "$output_file" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").rstrip("\r\n"), end="")
PY
)
  gate_cell=$(markdown_cell "$gate")
  command_cell=$(markdown_cell "$command")
  output=$(markdown_cell "$output")
  printf '| %s | `%s` | %s | %s |\n' \
    "$gate_cell" "$command_cell" "$status" "$output" >>"$report_rows"
}

coverage_output="$temporary_directory/coverage.out"
coverage_status=0
if [[ "$coverage_decision" == "executable" ]]; then
  if run_exact_command "$coverage_command" "$coverage_output"; then
    coverage_status=0
  else
    coverage_status=$?
    overall_status=1
  fi
  cat "$coverage_output"
  printf '\n'
  observed=$(
    python3 - "$coverage_output" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
matches = re.findall(r"(?m)(?:^|\s)coverage=([0-9]+(?:\.[0-9]+)?)(?:\s|$)", text)
if len(matches) != 1:
    print("coverage-policy: command must emit exactly one coverage=<percent>", file=sys.stderr)
    raise SystemExit(1)
print(matches[0])
PY
  ) || {
    overall_status=1
    observed=
  }
  if [[ -n "$observed" ]] && ! python3 - "$observed" "$baseline_percent" <<'PY'
from decimal import Decimal
import sys

observed, baseline = map(Decimal, sys.argv[1:])
if not Decimal("0") <= observed <= Decimal("100"):
    print("coverage-policy: observed coverage must be between 0 and 100", file=sys.stderr)
    raise SystemExit(1)
if observed < baseline:
    print(
        f"coverage regression: observed {observed:.2f} < baseline {baseline:.2f}",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
  then
    overall_status=1
  fi
  record_gate "coverage" "$coverage_command" "$coverage_status" "$coverage_output"
else
  printf 'coverage-policy: non-applicable through %s; approver=%s; reason=%s\n' \
    "$coverage_expiry" "$coverage_approver" "$coverage_reason"
fi

while IFS=$'\t' read -r gate command; do
  output_file="$temporary_directory/mapped-${gate//[^A-Za-z0-9]/_}.out"
  if run_exact_command "$command" "$output_file"; then
    status=0
  else
    status=$?
    overall_status=1
  fi
  cat "$output_file"
  printf '\n'
  record_gate "$gate" "$command" "$status" "$output_file"
done <"$gate_values"

spec_output="$temporary_directory/spec-lint.out"
spec_command="bash .tdd-swarm/spec-lint.sh $ticket_file $base_sha"
if bash .tdd-swarm/spec-lint.sh "$ticket_file" "$base_sha" >"$spec_output" 2>&1; then
  spec_status=0
else
  spec_status=$?
  overall_status=1
fi
cat "$spec_output"
printf '\n'
record_gate "spec-lint" "$spec_command" "$spec_status" "$spec_output"

import_output="$temporary_directory/import-cycles.out"
if python3 .tdd-swarm/check-import-cycles.py >"$import_output" 2>&1; then
  import_status=0
else
  import_status=$?
  overall_status=1
fi
cat "$import_output"
printf '\n'
record_gate \
  "import-cycles" \
  "python3 .tdd-swarm/check-import-cycles.py" \
  "$import_status" \
  "$import_output"

import_hash=$(python3 .tdd-swarm/check-import-cycles.py --hash-only 2>/dev/null) || import_hash="unavailable"

report_directory=".tdd-swarm/reports"
mkdir -p "$report_directory"
report_file="$report_directory/${ticket_id}-gates.md"
{
  printf '# Local gate report — %s\n\n' "$ticket_id"
  printf 'ticket: %s\n' "$ticket_file"
  printf 'base: %s\n' "$base_sha"
  printf 'head: %s\n' "$head_sha"
  printf 'coverage-policy-sha256: %s\n' "$policy_hash"
  printf 'import-graph-sha256: %s\n' "$import_hash"
  printf 'coverage-decision: %s\n' "$coverage_decision"
  if [[ "$coverage_decision" == "non-applicable" ]]; then
    printf 'coverage-reason: %s\n' "$coverage_reason"
    printf 'coverage-approver: %s\n' "$coverage_approver"
    printf 'coverage-date: %s\n' "$coverage_date"
    printf 'coverage-expiry: %s\n' "$coverage_expiry"
  else
    printf 'coverage-baseline-base-sha: %s\n' "$base_sha"
    printf 'coverage-baseline-percent: %s\n' "$baseline_percent"
  fi
  printf '\n| gate | exact command | exit | output |\n'
  printf '|---|---|---:|---|\n'
  cat "$report_rows"
} >"$report_file"

printf 'local-gates: report=%s\n' "$report_file"
exit "$overall_status"
