#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s <ticket-file> <diff-base>\n' "$0" >&2
  exit 2
fi

python3 - "$1" "$2" <<'PY'
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


def fail(message: str) -> None:
    print(f"spec-lint: {message}", file=sys.stderr)
    raise SystemExit(1)


repository = Path.cwd().absolute()
ticket_argument, diff_base = sys.argv[1:]


def safe_relative_file(value: str, *, required_parent: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        fail(f"unsafe repository path: {value}")
    if relative.parts[0] != required_parent:
        fail(f"path must be inside {required_parent}: {value}")
    current = repository
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            fail(f"missing file: {value}")
        if stat.S_ISLNK(status.st_mode):
            fail(f"refusing symlink path: {current.relative_to(repository)}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(status.st_mode):
            fail(f"non-directory path component: {current.relative_to(repository)}")
    if not stat.S_ISREG(os.lstat(current).st_mode):
        fail(f"not a regular file: {value}")
    return current


def snapshot(path: Path) -> tuple[tuple[int, int, int, int, int], str]:
    status = os.lstat(path)
    identity = (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
    )
    return identity, hashlib.sha256(path.read_bytes()).hexdigest()


ticket_path = safe_relative_file(ticket_argument, required_parent="tickets")
ticket_snapshot = snapshot(ticket_path)
try:
    ticket_text = ticket_path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as exc:
    fail(f"cannot read ticket: {exc}")

frontmatter_match = re.match(r"\A---\n(.*?)\n---(?:\n|\Z)", ticket_text, re.DOTALL)
if frontmatter_match is None:
    fail("ticket has no valid YAML frontmatter")
frontmatter = frontmatter_match.group(1)
ticket_ids = re.findall(r"(?m)^id:\s*([A-Za-z0-9-]+)\s*$", frontmatter)
if len(ticket_ids) != 1:
    fail("ticket must declare exactly one id")
ticket_id = ticket_ids[0]

test_scopes: list[str] = []
in_test_scopes = False
for line in frontmatter.splitlines():
    if re.fullmatch(r"test_scopes:\s*", line):
        in_test_scopes = True
        continue
    if in_test_scopes and re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:", line):
        break
    if not in_test_scopes:
        continue
    match = re.fullmatch(r"\s{2,}-\s+(.+?)\s*", line)
    if match:
        value = match.group(1)
        if value.startswith(("'", '"')) or any(character in value for character in "*?[]"):
            fail(f"unsupported test scope: {value}")
        test_scopes.append(value)
if not test_scopes:
    fail("ticket declares no test_scopes")
if len(test_scopes) != len(set(test_scopes)):
    fail("ticket declares a duplicate test scope")

acceptance_match = re.search(
    r"(?ms)^## Acceptance Criteria\s*$\n(.*?)(?=^## |\Z)",
    ticket_text,
)
if acceptance_match is None:
    fail("ticket has no Acceptance Criteria section")
criteria = set(
    re.findall(r"(?m)^-\s+\*\*(AC-[0-9]+)\*\*:", acceptance_match.group(1))
)
if not criteria:
    fail("ticket declares no acceptance criteria")

scope_paths = {
    scope: safe_relative_file(scope, required_parent="tests") for scope in test_scopes
}
scope_snapshots = {scope: snapshot(path) for scope, path in scope_paths.items()}

if not re.fullmatch(r"[0-9a-fA-F]{7,64}", diff_base):
    fail("diff-base must be a hexadecimal commit id")
resolved = subprocess.run(
    ["git", "rev-parse", "--verify", f"{diff_base}^{{commit}}"],
    cwd=repository,
    check=False,
    capture_output=True,
    text=True,
)
if resolved.returncode != 0:
    fail(f"invalid diff-base commit: {diff_base}")
base_sha = resolved.stdout.strip()


@dataclass(frozen=True)
class Candidate:
    qualified_name: str
    name: str
    line: int
    tags: tuple[tuple[str, str], ...]


tag_pattern = re.compile(r"spec\(([A-Za-z0-9-]+):(AC-[0-9]+)\)")
name_pattern = re.compile(
    rf"(?:^|_)spec_{re.escape(ticket_id.replace('-', '_'))}_AC_([0-9]+)(?:_|$)"
)


def parsed_candidates(source: str, filename: str) -> dict[str, Candidate]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        fail(f"cannot parse {filename}: {exc}")
    lines = source.splitlines()
    found: dict[str, Candidate] = {}

    def visit(body: list[ast.stmt], parents: tuple[str, ...]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = "::".join((*parents, node.name))
                if node.name.startswith("test"):
                    docstring = ast.get_docstring(node, clean=False) or ""
                    tags = list(tag_pattern.findall(docstring))
                    starts = [node.lineno, *(item.lineno for item in node.decorator_list)]
                    comment_line = min(starts) - 1
                    while comment_line > 0:
                        text = lines[comment_line - 1].strip()
                        if not text.startswith("#"):
                            break
                        tags.extend(tag_pattern.findall(text))
                        comment_line -= 1
                    for match in name_pattern.finditer(node.name):
                        tags.append((ticket_id, f"AC-{match.group(1)}"))
                    found[qualified] = Candidate(
                        qualified,
                        node.name,
                        node.lineno,
                        tuple(dict.fromkeys(tags)),
                    )
                visit(node.body, (*parents, node.name))
            elif isinstance(node, ast.ClassDef):
                visit(node.body, (*parents, node.name))

    visit(tree.body, ())
    return found


current_candidates: dict[str, dict[str, Candidate]] = {}
base_candidates: dict[str, set[str]] = {}
for scope, path in scope_paths.items():
    try:
        current_source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read {scope}: {exc}")
    current_candidates[scope] = parsed_candidates(current_source, scope)

    prior = subprocess.run(
        ["git", "show", f"{base_sha}:{scope}"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if prior.returncode == 0:
        base_candidates[scope] = set(parsed_candidates(prior.stdout, f"{base_sha}:{scope}"))
    else:
        base_candidates[scope] = set()


def candidate_python() -> str:
    candidates: list[str] = []

    if os.environ.get("__PYVENV_LAUNCHER__"):
        candidates.append(os.environ["__PYVENV_LAUNCHER__"])
    local_python = repository / ".venv" / "bin" / "python"
    if local_python.is_file():
        candidates.append(str(local_python))
    candidates.append(sys.executable)

    pid = os.getppid()
    for _ in range(16):
        if pid <= 1:
            break
        cwd_link = Path(f"/proc/{pid}/cwd")
        if cwd_link.exists():
            try:
                candidates.append(str(Path(os.readlink(cwd_link)) / ".venv/bin/python"))
            except OSError:
                pass
        else:
            cwd_result = subprocess.run(
                ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                check=False,
                capture_output=True,
                text=True,
            )
            for line in cwd_result.stdout.splitlines():
                if line.startswith("n/"):
                    candidates.append(str(Path(line[1:]) / ".venv/bin/python"))
        executable_link = Path(f"/proc/{pid}/exe")
        if executable_link.exists():
            try:
                candidates.append(os.readlink(executable_link))
            except OSError:
                pass
        process = subprocess.run(
            ["ps", "-p", str(pid), "-o", "ppid=", "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
        )
        if process.returncode != 0 or not process.stdout.strip():
            break
        match = re.match(r"\s*([0-9]+)\s+(.*)", process.stdout.strip(), re.DOTALL)
        if match is None:
            break
        parent_text, command = match.groups()
        try:
            words = shlex.split(command)
        except ValueError:
            words = command.split()
        if words:
            candidates.append(words[0])
        pid = int(parent_text)

    seen: set[str] = set()
    for executable in candidates:
        if executable in seen:
            continue
        seen.add(executable)
        if not Path(executable).name.lower().startswith("python"):
            continue
        try:
            check = subprocess.run(
                [executable, "-c", "import pytest"],
                cwd=repository,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if check.returncode == 0:
            return executable
    fail("real pytest collection is unavailable")
    raise AssertionError


collector_source = r'''
import json
import os
import re
import sys

import pytest
from _pytest.skipping import evaluate_skip_marks


class Observer:
    def __init__(self, scopes):
        self.scopes = {scope.replace(os.sep, "/") for scope in scopes}
        self.items = []
        self.failures = []
        self.collector_skips = []

    @pytest.hookimpl(tryfirst=True)
    def pytest_ignore_collect(self, collection_path, config):
        relative = os.path.relpath(str(collection_path), os.getcwd()).replace(os.sep, "/")
        if relative in self.scopes:
            return None
        prefix = relative.rstrip("/") + "/"
        if any(scope.startswith(prefix) for scope in self.scopes):
            return None
        return True

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        for item in items:
            parts = item.nodeid.split("::")
            qualified = "::".join(re.sub(r"\[.*\]$", "", part) for part in parts[1:])
            skipped = evaluate_skip_marks(item) is not None
            self.items.append(
                {
                    "scope": parts[0].replace(os.sep, "/"),
                    "qualified": qualified,
                    "nodeid": item.nodeid,
                    "skipped": skipped,
                }
            )

    def pytest_collectreport(self, report):
        if report.failed:
            self.failures.append(
                {"nodeid": report.nodeid, "diagnostic": str(report.longrepr)}
            )
        elif report.skipped:
            self.collector_skips.append(report.nodeid)


result_path = sys.argv[1]
scopes = json.loads(sys.argv[2])
collection_roots = sys.argv[3:]
observer = Observer(scopes)
status = pytest.main(
    ["-p", "no:cacheprovider", "--collect-only", "-q", *collection_roots],
    plugins=[observer],
)
with open(result_path, "w", encoding="utf-8") as stream:
    json.dump(
        {
            "status": int(status),
            "items": observer.items,
            "failures": observer.failures,
            "collector_skips": observer.collector_skips,
        },
        stream,
        sort_keys=True,
    )
'''

with tempfile.TemporaryDirectory(prefix="tdd-swarm-spec-") as temporary:
    observation_path = Path(temporary) / "collection.json"
    collection_roots = sorted({str(Path(scope).parent) for scope in test_scopes})
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    collection = subprocess.run(
        [
            candidate_python(),
            "-c",
            collector_source,
            str(observation_path),
            json.dumps(test_scopes),
            *collection_roots,
        ],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    if not observation_path.is_file():
        diagnostic = (collection.stdout + collection.stderr).strip()
        fail(f"pytest collection failed before observation: {diagnostic}")
    observation = json.loads(observation_path.read_text(encoding="utf-8"))

if snapshot(ticket_path) != ticket_snapshot:
    fail("ticket changed during pytest collection")
for scope, path in scope_paths.items():
    if snapshot(path) != scope_snapshots[scope]:
        fail(f"test scope changed during pytest collection: {scope}")

collected: dict[str, set[str]] = {scope: set() for scope in test_scopes}
skipped: dict[str, set[str]] = {scope: set() for scope in test_scopes}
for item in observation["items"]:
    scope = item["scope"]
    if scope not in collected:
        continue
    qualified = item["qualified"]
    collected[scope].add(qualified)
    if item["skipped"]:
        skipped[scope].add(qualified)

collection_failed = bool(observation["failures"])
errors: list[str] = []
mapped: set[str] = set()
for scope in test_scopes:
    for qualified, candidate in current_candidates[scope].items():
        location = f"{scope}:{candidate.line}: {candidate.name}"
        is_new = qualified not in base_candidates[scope]
        if is_new and not candidate.tags:
            errors.append(f"{location} missing spec({ticket_id}:AC-n)")

        valid_tags: set[str] = set()
        for tagged_ticket, criterion in candidate.tags:
            if tagged_ticket != ticket_id:
                errors.append(
                    f"{location} maps wrong ticket {tagged_ticket}; expected {ticket_id}"
                )
            elif criterion not in criteria:
                errors.append(f"{location} maps nonexistent criterion {criterion}")
            else:
                valid_tags.add(criterion)

        if not valid_tags:
            continue
        if qualified not in collected[scope]:
            detail = "collection failed" if collection_failed else "not collected"
            errors.append(f"{location} is {detail} by pytest and cannot map an acceptance criterion")
            continue
        if qualified in skipped[scope]:
            errors.append(f"{location} is skipped by pytest and cannot map an acceptance criterion")
            continue
        mapped.update(valid_tags)

for criterion in sorted(criteria - mapped):
    errors.append(f"{criterion} has no spec({ticket_id}:{criterion}) collected test mapping")

if errors:
    for error in dict.fromkeys(errors):
        print(f"spec-lint: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"spec-lint: {ticket_id} maps {len(criteria)} acceptance criteria "
    f"across {len(test_scopes)} pytest-collected scopes"
)
PY
