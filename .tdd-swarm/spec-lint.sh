#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s <ticket-file> <diff-base>\n' "$0" >&2
  exit 2
fi

ticket_file=$1
diff_base=$2

if [[ ! -f "$ticket_file" || -L "$ticket_file" ]]; then
  printf 'spec-lint: ticket is not a regular file: %s\n' "$ticket_file" >&2
  exit 1
fi
if [[ ! "$diff_base" =~ ^[0-9a-fA-F]{7,64}$ ]]; then
  printf 'spec-lint: diff-base must be a hexadecimal commit id\n' >&2
  exit 1
fi
if ! git rev-parse --verify "${diff_base}^{commit}" >/dev/null 2>&1; then
  printf 'spec-lint: invalid diff-base commit: %s\n' "$diff_base" >&2
  exit 1
fi

python3 - "$ticket_file" <<'PY'
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

repository = Path.cwd().resolve()
ticket_path = Path(sys.argv[1])
try:
    ticket_path.resolve(strict=True).relative_to(repository / "tickets")
except (OSError, ValueError):
    print("spec-lint: ticket must resolve inside the repository tickets directory", file=sys.stderr)
    raise SystemExit(1)

try:
    ticket_text = ticket_path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as exc:
    print(f"spec-lint: cannot read ticket: {exc}", file=sys.stderr)
    raise SystemExit(1)

frontmatter_match = re.match(r"\A---\n(.*?)\n---(?:\n|\Z)", ticket_text, re.DOTALL)
if frontmatter_match is None:
    print("spec-lint: ticket has no valid YAML frontmatter", file=sys.stderr)
    raise SystemExit(1)

frontmatter = frontmatter_match.group(1)
ticket_ids = re.findall(r"(?m)^id:\s*([A-Za-z0-9-]+)\s*$", frontmatter)
if len(ticket_ids) != 1:
    print("spec-lint: ticket must declare exactly one id", file=sys.stderr)
    raise SystemExit(1)
ticket_id = ticket_ids[0]

test_scopes: list[str] = []
in_test_scopes = False
for line in frontmatter.splitlines():
    if re.fullmatch(r"test_scopes:\s*", line):
        in_test_scopes = True
        continue
    if in_test_scopes and re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:", line):
        break
    if in_test_scopes:
        match = re.fullmatch(r"\s{2,}-\s+(.+?)\s*", line)
        if match:
            value = match.group(1)
            if value.startswith(("'", '"')) or any(char in value for char in "*?[]"):
                print(f"spec-lint: unsupported test scope: {value}", file=sys.stderr)
                raise SystemExit(1)
            test_scopes.append(value)

if not test_scopes:
    print("spec-lint: ticket declares no test_scopes", file=sys.stderr)
    raise SystemExit(1)

acceptance_match = re.search(
    r"(?ms)^## Acceptance Criteria\s*$\n(.*?)(?=^## |\Z)", ticket_text
)
if acceptance_match is None:
    print("spec-lint: ticket has no Acceptance Criteria section", file=sys.stderr)
    raise SystemExit(1)
criteria = set(re.findall(r"(?m)^-\s+\*\*(AC-[0-9]+)\*\*:", acceptance_match.group(1)))
if not criteria:
    print("spec-lint: ticket declares no acceptance criteria", file=sys.stderr)
    raise SystemExit(1)

tag_pattern = re.compile(r"spec\(([A-Za-z0-9-]+):(AC-[0-9]+)\)")
mapped: set[str] = set()
errors: list[str] = []

for scope in test_scopes:
    path = Path(scope)
    try:
        path.resolve(strict=True).relative_to(repository / "tests")
    except (OSError, ValueError):
        errors.append(f"test scope escapes repository tests directory: {scope}")
        continue
    if not path.is_file() or path.is_symlink():
        errors.append(f"missing test scope: {scope}")
        continue
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=scope)
    except (OSError, UnicodeError, SyntaxError) as exc:
        errors.append(f"cannot parse {scope}: {exc}")
        continue

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test"):
            continue
        docstring = ast.get_docstring(node, clean=False) or ""
        tags = tag_pattern.findall(docstring)
        if not tags:
            errors.append(f"{scope}:{node.lineno}: {node.name} missing spec({ticket_id}:AC-n)")
            continue
        for tagged_ticket, criterion in tags:
            if tagged_ticket != ticket_id:
                errors.append(
                    f"{scope}:{node.lineno}: {node.name} maps wrong ticket "
                    f"{tagged_ticket}; expected {ticket_id}"
                )
                continue
            if criterion not in criteria:
                errors.append(
                    f"{scope}:{node.lineno}: {node.name} maps nonexistent criterion {criterion}"
                )
                continue
            mapped.add(criterion)

for criterion in sorted(criteria - mapped):
    errors.append(f"{criterion} has no spec({ticket_id}:{criterion}) test mapping")

if errors:
    for error in errors:
        print(f"spec-lint: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"spec-lint: {ticket_id} maps {len(criteria)} acceptance criteria "
    f"across {len(test_scopes)} test scopes"
)
PY
