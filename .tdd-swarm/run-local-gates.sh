#!/usr/bin/env bash
set -euo pipefail

exec python3 - "$@" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

OUTPUT_LIMIT = 16_384
DEFAULT_TIMEOUT = 30.0
CORE_PATHS = (
    ".tdd-swarm/run-local-gates.sh",
    ".tdd-swarm/spec-lint.sh",
    ".tdd-swarm/check-import-cycles.py",
    ".tdd-swarm/publish-report.py",
)
POLICY_PATH = ".tdd-swarm/coverage-policy.md"
GATE_MAP_PATH = ".tdd-swarm/gates.md"

PROTECTED_GATES: dict[str, tuple[str, tuple[str, ...]]] = {
    "format": (
        ".venv/bin/ruff format --check .",
        (".venv/bin/ruff", "format", "--check", "."),
    ),
    "lint": (
        ".venv/bin/ruff check .",
        (".venv/bin/ruff", "check", "."),
    ),
    "typecheck": (
        ".venv/bin/mypy --config-file pyproject.toml src tests",
        (".venv/bin/mypy", "--config-file", "pyproject.toml", "src", "tests"),
    ),
    "unit": (
        ".venv/bin/pytest",
        (".venv/bin/pytest",),
    ),
    "secret-scan": (
        "bash scripts/secret_scan.sh",
        ("bash", "scripts/secret_scan.sh"),
    ),
}
PROTECTED_COVERAGE_ADAPTERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "pytest-cov": (".venv/bin/pytest", (".venv/bin/pytest",)),
}


class FatalGateError(Exception):
    def __init__(self, message: str, status: int = 1) -> None:
        super().__init__(message)
        self.status = status


def fatal(message: str, status: int = 1) -> None:
    raise FatalGateError(message, status)


repository = Path.cwd().absolute()


def git(arguments: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
    )


def safe_repository_path(
    relative_text: str,
    *,
    file_required: bool = True,
    required_prefix: str | None = None,
) -> Path:
    relative = Path(relative_text)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        fatal(f"unsafe repository path: {relative_text}")
    if required_prefix is not None and relative.parts[0] != required_prefix:
        fatal(f"path must remain inside {required_prefix}: {relative_text}")

    current = repository
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            fatal(f"required path is absent: {relative_text}")
        if stat.S_ISLNK(status.st_mode):
            fatal(f"refusing symlink path: {current.relative_to(repository)}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(status.st_mode):
            fatal(f"non-directory path component: {current.relative_to(repository)}")
    final_status = os.lstat(current)
    if file_required and not stat.S_ISREG(final_status.st_mode):
        fatal(f"path is not a regular file: {relative_text}")
    if not file_required and not stat.S_ISDIR(final_status.st_mode):
        fatal(f"path is not a directory: {relative_text}")
    return current


def reject_symlink_if_present(relative_text: str) -> None:
    relative = Path(relative_text)
    current = repository
    for part in relative.parts:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(status.st_mode):
            fatal(f"refusing symlink path: {current.relative_to(repository)}")


@dataclass(frozen=True)
class Snapshot:
    path: Path
    identity: tuple[int, int, int, int, int]
    content: bytes
    digest: str


def take_snapshot(path: Path) -> Snapshot:
    status = os.lstat(path)
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        fatal(f"input is not a regular non-symlink file: {path}")
    content = path.read_bytes()
    identity = (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
    )
    return Snapshot(path, identity, content, hashlib.sha256(content).hexdigest())


def snapshot_matches(value: Snapshot) -> bool:
    try:
        status = os.lstat(value.path)
    except FileNotFoundError:
        return False
    identity = (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
    )
    if identity != value.identity or stat.S_ISLNK(status.st_mode):
        return False
    try:
        return hashlib.sha256(value.path.read_bytes()).hexdigest() == value.digest
    except OSError:
        return False


def parse_ticket(content: bytes) -> tuple[str, list[str]]:
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        fatal(f"ticket is not UTF-8: {exc}")
    frontmatter_match = re.match(r"\A---\n(.*?)\n---(?:\n|\Z)", text, re.DOTALL)
    if frontmatter_match is None:
        fatal("ticket has no valid frontmatter")
    frontmatter = frontmatter_match.group(1)
    identifiers = re.findall(r"(?m)^id:\s*([A-Za-z0-9-]+)\s*$", frontmatter)
    if len(identifiers) != 1:
        fatal("ticket must declare exactly one safe id")

    scopes: list[str] = []
    in_scopes = False
    for line in frontmatter.splitlines():
        if re.fullmatch(r"test_scopes:\s*", line):
            in_scopes = True
            continue
        if in_scopes and re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:", line):
            break
        if in_scopes:
            match = re.fullmatch(r"\s{2,}-\s+(.+?)\s*", line)
            if match:
                scope = match.group(1)
                if scope.startswith(("'", '"')) or any(char in scope for char in "*?[]"):
                    fatal(f"unsupported test scope: {scope}")
                scopes.append(scope)
    if not scopes:
        fatal("ticket declares no test scopes")
    if len(scopes) != len(set(scopes)):
        fatal("ticket declares duplicate test scopes")
    return identifiers[0], scopes


def committed_bytes(commit: str, relative: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=repository,
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def require_committed_match(commit: str, relative: str, path: Path) -> None:
    expected = committed_bytes(commit, relative)
    if expected is None or expected != path.read_bytes():
        fatal(f"protected executable integrity mismatch: {relative}")


def parse_gate_map(content: bytes) -> list[tuple[str, str, str, tuple[str, ...] | None]]:
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        fatal(f"gate map is not UTF-8: {exc}")
    rows: list[tuple[str, str, str, tuple[str, ...] | None]] = []
    seen: set[str] = set()
    in_table = False
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.strip().lower() == "| gate | exact command | current status |":
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
            fatal(f"gates: malformed table row {line_number}")
        gate_name, command, status_text = cells
        if set(gate_name) <= {"-", ":"}:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", gate_name):
            fatal(f"gates: unsafe gate id on row {line_number}")
        if gate_name in seen:
            fatal(f"gates: duplicate gate id {gate_name}")
        seen.add(gate_name)

        if status_text == "AVAILABLE":
            protected = PROTECTED_GATES.get(gate_name)
            if protected is None:
                if command.startswith(("sh -c", "bash -c")):
                    fatal(f"gates: unsanctioned shell vector for {gate_name}")
                fatal(f"gates: {gate_name} has no fixed sanctioned command authority")
            expected_display, arguments = protected
            if command != expected_display:
                if command.startswith(("sh -c", "bash -c")):
                    fatal(f"gates: unsanctioned shell vector for {gate_name}")
                fatal(f"gates: fixed argument mapping mismatch for {gate_name}")
            rows.append((gate_name, command, status_text, arguments))
        elif status_text in {"SKIPPED", "BLOCKED"}:
            if not command.startswith("reason=") or not command.removeprefix("reason=").strip():
                fatal(f"gates: {status_text} row {gate_name} requires reason=...")
            rows.append((gate_name, command, status_text, None))
        else:
            fatal(f"gates: invalid status for {gate_name}: {status_text}")
    if not rows:
        fatal("gates: no declared gate rows")
    return rows


def parse_policy(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        fatal(f"coverage-policy is not UTF-8: {exc}")
    fields: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([a-z][a-z0-9-]*):[ \t]*(.*)", line)
        if match is None:
            fatal(f"coverage-policy: malformed line {line_number}")
        key, value = match.groups()
        if key in fields:
            fatal(f"coverage-policy: duplicate field {key}")
        fields[key] = value.strip()

    decision = fields.get("decision")
    if decision == "non-applicable":
        allowed = {"decision", "reason", "approver", "date", "expiry"}
        for required in ("reason", "approver", "date", "expiry"):
            if not fields.get(required):
                fatal(f"coverage-policy: missing {required}")
        try:
            approved = date.fromisoformat(fields["date"])
            expires = date.fromisoformat(fields["expiry"])
        except ValueError:
            fatal("coverage-policy: date and expiry must be ISO dates")
        if approved > date.today():
            fatal("coverage-policy: approval date is in the future")
        if expires < date.today():
            fatal(f"coverage-policy: waiver expired on {expires}")
    elif decision == "executable":
        allowed = {
            "decision",
            "coverage-adapter",
            "baseline-base-sha",
            "baseline-percent",
        }
        for required in ("coverage-adapter", "baseline-base-sha", "baseline-percent"):
            if not fields.get(required):
                label = "base-SHA" if required == "baseline-base-sha" else required
                fatal(f"coverage-policy: missing {label}")
        if fields["coverage-adapter"] not in PROTECTED_COVERAGE_ADAPTERS:
            fatal("coverage-policy: unknown coverage adapter")
        try:
            baseline = Decimal(fields["baseline-percent"])
        except InvalidOperation:
            fatal("coverage-policy: baseline-percent is not numeric")
        if not Decimal("0") <= baseline <= Decimal("100"):
            fatal("coverage-policy: baseline-percent must be between 0 and 100")
    else:
        allowed = {"decision"}
        fatal("coverage-policy: decision must be executable or non-applicable")

    unknown = sorted(set(fields) - allowed)
    if unknown:
        fatal(f"coverage-policy: unknown coverage fields: {', '.join(unknown)}")
    return fields


def safe_external_file(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        labels = {
            "TDD_SWARM_COVERAGE_APPROVAL_FILE": "record",
            "TDD_SWARM_COVERAGE_APPROVAL_SIGNATURE_FILE": "signature",
            "TDD_SWARM_COVERAGE_APPROVAL_PUBLIC_KEY_FILE": "public key",
        }
        fatal(
            "coverage policy requires an external approval "
            f"{labels.get(variable, 'artifact')} file"
        )
    path = Path(value)
    if not path.is_absolute():
        path = repository / path
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            fatal(f"coverage approval file is absent: {variable}")
        if stat.S_ISLNK(status.st_mode):
            fatal(f"coverage approval file uses a symlink: {variable}")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        fatal(f"coverage approval path is not a regular file: {variable}")
    return path


def verify_non_applicable_approval(
    *,
    policy_snapshot: Snapshot,
    head_sha: str,
) -> list[Snapshot]:
    record_path = safe_external_file("TDD_SWARM_COVERAGE_APPROVAL_FILE")
    signature_path = safe_external_file("TDD_SWARM_COVERAGE_APPROVAL_SIGNATURE_FILE")
    public_key_path = safe_external_file("TDD_SWARM_COVERAGE_APPROVAL_PUBLIC_KEY_FILE")
    external = [
        take_snapshot(record_path),
        take_snapshot(signature_path),
        take_snapshot(public_key_path),
    ]
    try:
        record = json.loads(external[0].content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        fatal("coverage approval record is not valid JSON")
    required = {"schema_version", "policy_sha256", "commit_sha", "approver_id"}
    if not isinstance(record, dict) or set(record) != required:
        fatal("coverage approval record has an invalid schema")
    if record.get("schema_version") != 1:
        fatal("coverage approval record has an unsupported schema version")
    if record.get("policy_sha256") != policy_snapshot.digest:
        fatal("coverage approval policy hash does not match")
    if record.get("commit_sha") != head_sha:
        fatal("coverage approval commit does not match starting HEAD")
    allowed = {
        item.strip()
        for item in os.environ.get("TDD_SWARM_COVERAGE_APPROVER_IDS", "").split(",")
        if item.strip()
    }
    if not allowed or record.get("approver_id") not in allowed:
        fatal("coverage approval approver identity is not authorized")

    verification = run_bounded(
        (
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-sigfile",
            str(signature_path),
            "-in",
            str(record_path),
        ),
        10.0,
    )
    if verification.code != 0:
        fatal("coverage approval detached signature verification failed")
    return external


def configured_secrets() -> list[bytes]:
    sensitive = re.compile(r"(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|PRIVATE_KEY)")
    values: set[bytes] = set()
    for key, value in os.environ.items():
        if sensitive.search(key.upper()) and len(value) >= 4:
            values.add(value.encode("utf-8", errors="ignore"))
    return sorted((value for value in values if value), key=len, reverse=True)


SECRET_VALUES = configured_secrets()
KNOWN_SECRET_PATTERNS = (
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


def redact(raw: bytes) -> bytes:
    value = raw
    for secret in SECRET_VALUES:
        value = value.replace(secret, b"[REDACTED]")
    for pattern in KNOWN_SECRET_PATTERNS:
        value = pattern.sub(b"[REDACTED]", value)
    return value


def canonical_markdown(raw: bytes) -> str:
    text = redact(raw).decode("utf-8", errors="replace")
    encoded: list[str] = []
    index = 0
    while index < len(text):
        character = text[index]
        codepoint = ord(character)
        if character == "\r" and index + 1 < len(text) and text[index + 1] == "\n":
            index += 1
        elif character in {"\r", "\n"}:
            encoded.append("<br>")
        elif character == "<":
            encoded.append("&lt;")
        elif character == ">":
            encoded.append("&gt;")
        elif character == "&":
            encoded.append("&amp;")
        elif character == "`":
            encoded.append("&#x60;")
        elif character == "|":
            encoded.append("&#x7C;")
        elif character == "\\":
            encoded.append("&#x5C;")
        elif codepoint == 0x1B:
            encoded.append("&#x1B;")
        elif codepoint < 0x20 or codepoint == 0x7F:
            encoded.append(f"&#x{codepoint:02X};")
        else:
            encoded.append(character)
        index += 1
    return "".join(encoded)


def emit_safe(raw: bytes) -> None:
    rendered = canonical_markdown(raw)
    if rendered:
        print(rendered)


@dataclass
class CommandResult:
    code: int
    raw: bytes
    diagnostic: str | None = None

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    @property
    def report_output(self) -> str:
        rendered = canonical_markdown(self.raw)
        if self.diagnostic:
            suffix = canonical_markdown(self.diagnostic.encode("utf-8"))
            rendered = f"{rendered}<br>{suffix}" if rendered else suffix
        return rendered


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.15)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_bounded(arguments: tuple[str, ...] | list[str], timeout_seconds: float) -> CommandResult:
    try:
        process = subprocess.Popen(
            list(arguments),
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        return CommandResult(127, f"command start error: {exc}\n".encode())

    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    captured = bytearray()
    deadline = time.monotonic() + timeout_seconds
    eof = False
    timed_out = False
    over_limit = False

    while True:
        if len(captured) > OUTPUT_LIMIT:
            over_limit = True
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        if eof and process.poll() is not None:
            break
        events = selector.select(min(remaining, 0.05))
        if events:
            try:
                data = os.read(descriptor, max(1, OUTPUT_LIMIT + 1 - len(captured)))
            except BlockingIOError:
                data = b""
            if data:
                captured.extend(data)
            else:
                eof = True
                try:
                    selector.unregister(descriptor)
                except KeyError:
                    pass
        elif process.poll() is not None:
            try:
                data = os.read(descriptor, max(1, OUTPUT_LIMIT + 1 - len(captured)))
            except BlockingIOError:
                data = b""
            if data:
                captured.extend(data)
            else:
                eof = True

    selector.close()
    if timed_out or over_limit:
        stop_process_group(process)
        raw = bytes(captured[:OUTPUT_LIMIT])
        if timed_out:
            return CommandResult(124, raw, "timeout: process group terminated")
        return CommandResult(125, raw, "output limit exceeded; output truncated at 16384 bytes")

    code = process.wait()
    return CommandResult(code if 0 <= code <= 255 else 1, bytes(captured))


def wait_failpoint(name: str) -> None:
    if os.environ.get("TDD_SWARM_TEST_FAILPOINT") != name:
        return
    ready_value = os.environ.get("TDD_SWARM_TEST_FAILPOINT_READY_FILE")
    continue_value = os.environ.get("TDD_SWARM_TEST_FAILPOINT_CONTINUE_FILE")
    if not ready_value or not continue_value:
        fatal(f"test failpoint {name} lacks ready/continue paths")
    ready = Path(ready_value)
    continuation = Path(continue_value)
    ready.touch()
    deadline = time.monotonic() + 30
    while not continuation.exists():
        if time.monotonic() >= deadline:
            fatal(f"test failpoint {name} timed out")
        time.sleep(0.01)


@dataclass
class ReportRow:
    gate: str
    command: str
    exit_value: str
    output: str
    digest: str | None


def aggregate_scope_hash(scopes: list[tuple[str, Snapshot]]) -> str:
    payload = bytearray()
    for relative, value in sorted(scopes, key=lambda item: item[0].encode("utf-8")):
        path_bytes = relative.encode("utf-8")
        payload.extend(len(path_bytes).to_bytes(4, "big"))
        payload.extend(path_bytes)
        payload.extend(len(value.content).to_bytes(8, "big"))
        payload.extend(value.content)
    return hashlib.sha256(payload).hexdigest()


def revalidate_inputs(values: list[Snapshot]) -> None:
    for value in values:
        if not snapshot_matches(value):
            fatal(f"validated input changed or became a symlink: {value.path}")


def stage_report(ticket_id: str, report_bytes: bytes) -> tuple[Path, Path]:
    swarm_path = safe_repository_path(".tdd-swarm", file_required=False)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    swarm_fd = os.open(swarm_path, os.O_RDONLY | os.O_DIRECTORY | nofollow)
    try:
        try:
            reports_status = os.stat("reports", dir_fd=swarm_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir("reports", mode=0o700, dir_fd=swarm_fd)
            reports_status = os.stat("reports", dir_fd=swarm_fd, follow_symlinks=False)
        if not stat.S_ISDIR(reports_status.st_mode):
            fatal("report directory is a symlink or is not a real directory")
        reports_fd = os.open(
            "reports",
            os.O_RDONLY | os.O_DIRECTORY | nofollow,
            dir_fd=swarm_fd,
        )
    except OSError as exc:
        os.close(swarm_fd)
        fatal(f"report directory symlink/integrity failure: {exc}")
    os.close(swarm_fd)

    destination_name = f"{ticket_id}-gates.md"
    try:
        try:
            destination_status = os.stat(
                destination_name,
                dir_fd=reports_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            destination_status = None
        if destination_status is not None and not stat.S_ISREG(destination_status.st_mode):
            fatal("report destination is a symlink or not a regular file")

        stage_name = ""
        stage_fd = -1
        for _ in range(32):
            stage_name = f".{ticket_id}-gates.{secrets.token_hex(12)}.stage"
            try:
                stage_fd = os.open(
                    stage_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                    0o600,
                    dir_fd=reports_fd,
                )
                break
            except FileExistsError:
                continue
        if stage_fd < 0:
            fatal("could not allocate an unpredictable report stage")
        try:
            view = memoryview(report_bytes)
            written = 0
            while written < len(view):
                written += os.write(stage_fd, view[written:])
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
    finally:
        os.close(reports_fd)

    report_directory = repository / ".tdd-swarm" / "reports"
    return report_directory / stage_name, report_directory / destination_name


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <ticket-file> <diff-base>", file=sys.stderr)
        return 2
    ticket_argument, diff_base = sys.argv[1:]
    ticket_path = safe_repository_path(
        ticket_argument,
        required_prefix="tickets",
    )
    policy_path = safe_repository_path(POLICY_PATH)
    gate_map_path = safe_repository_path(GATE_MAP_PATH)
    core_paths = {relative: safe_repository_path(relative) for relative in CORE_PATHS}
    reject_symlink_if_present("src")
    reject_symlink_if_present("src/agentforge")

    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", diff_base):
        fatal("diff-base must be a hexadecimal commit id")
    base_result = git(["rev-parse", "--verify", f"{diff_base}^{{commit}}"])
    if base_result.returncode != 0:
        fatal(f"invalid diff-base commit: {diff_base}")
    base_sha = base_result.stdout.strip()
    head_result = git(["rev-parse", "--verify", "HEAD^{commit}"])
    if head_result.returncode != 0:
        fatal("cannot resolve starting HEAD")
    head_sha = head_result.stdout.strip()
    ancestry = git(["merge-base", "--is-ancestor", base_sha, head_sha])
    if ancestry.returncode != 0:
        fatal("supplied diff-base is not an ancestor of starting HEAD")

    ticket_snapshot = take_snapshot(ticket_path)
    policy_snapshot = take_snapshot(policy_path)
    gate_map_snapshot = take_snapshot(gate_map_path)
    core_snapshots = {
        relative: take_snapshot(path) for relative, path in core_paths.items()
    }
    ticket_id, test_scope_names = parse_ticket(ticket_snapshot.content)
    test_scope_snapshots: list[tuple[str, Snapshot]] = []
    for scope in test_scope_names:
        scope_path = safe_repository_path(scope, required_prefix="tests")
        dirty = git(["status", "--porcelain=v1", "--untracked-files=all", "--", scope])
        if dirty.returncode != 0 or dirty.stdout:
            fatal(f"dirty tested worktree path: {scope}")
        if committed_bytes(head_sha, scope) != scope_path.read_bytes():
            fatal(f"dirty frozen test scope: {scope}")
        test_scope_snapshots.append((scope, take_snapshot(scope_path)))

    for relative, path in core_paths.items():
        require_committed_match(head_sha, relative, path)

    policy = parse_policy(policy_snapshot.content)
    gate_rows = parse_gate_map(gate_map_snapshot.content)
    external_snapshots: list[Snapshot] = []
    if policy["decision"] == "non-applicable":
        external_snapshots = verify_non_applicable_approval(
            policy_snapshot=policy_snapshot,
            head_sha=head_sha,
        )
    else:
        baseline_text = policy["baseline-base-sha"]
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", baseline_text):
            fatal("coverage-policy baseline base-SHA must be a hexadecimal commit id")
        baseline_result = git(["rev-parse", "--verify", f"{baseline_text}^{{commit}}"])
        if baseline_result.returncode != 0:
            fatal("coverage-policy baseline base-SHA is not a commit")
        if baseline_result.stdout.strip() != base_sha:
            fatal("coverage-policy baseline base-SHA does not match supplied diff-base")

    mapped_script_snapshots: list[Snapshot] = []
    for _, _, status_text, arguments in gate_rows:
        if status_text != "AVAILABLE" or arguments is None:
            continue
        if len(arguments) >= 2 and arguments[0] in {"bash", "python3"}:
            relative = arguments[1]
            if relative.startswith(".") or relative.startswith("scripts/"):
                path = safe_repository_path(relative)
                require_committed_match(head_sha, relative, path)
                mapped_script_snapshots.append(take_snapshot(path))

    all_input_snapshots = [
        ticket_snapshot,
        policy_snapshot,
        gate_map_snapshot,
        *core_snapshots.values(),
        *(value for _, value in test_scope_snapshots),
        *mapped_script_snapshots,
        *external_snapshots,
    ]
    wait_failpoint("after-input-validation-before-use")
    revalidate_inputs(all_input_snapshots)

    timeout_text = os.environ.get(
        "TDD_SWARM_GATE_TIMEOUT_SECONDS",
        str(DEFAULT_TIMEOUT),
    )
    try:
        timeout_seconds = float(timeout_text)
    except ValueError:
        fatal("gate timeout must be a positive number")
    if not 0 < timeout_seconds <= 3600:
        fatal("gate timeout must be a positive bounded number")

    report_rows: list[ReportRow] = []
    overall_pass = True
    coverage_validation_status = "PASS"
    coverage_diagnostic = ""

    if policy["decision"] == "executable":
        adapter_display, adapter_arguments = PROTECTED_COVERAGE_ADAPTERS[
            policy["coverage-adapter"]
        ]
        coverage_result = run_bounded(adapter_arguments, timeout_seconds)
        emit_safe(coverage_result.raw)
        if coverage_result.diagnostic:
            print(f"coverage-policy: {coverage_result.diagnostic}", file=sys.stderr)
        report_rows.append(
            ReportRow(
                "coverage",
                adapter_display,
                str(coverage_result.code),
                coverage_result.report_output,
                coverage_result.digest,
            )
        )
        if coverage_result.code != 0:
            overall_pass = False
            coverage_validation_status = "FAIL"
            coverage_diagnostic = "coverage adapter process failed"
        text = coverage_result.raw.decode("utf-8", errors="replace")
        matches = re.findall(
            r"(?m)(?:^|\s)coverage=([0-9]+(?:\.[0-9]+)?)(?:\s|$)",
            text,
        )
        if len(matches) != 1:
            overall_pass = False
            coverage_validation_status = "FAIL"
            coverage_diagnostic = "coverage adapter must emit exactly one coverage=<percent>"
            print(f"coverage-policy: {coverage_diagnostic}", file=sys.stderr)
        else:
            observed = Decimal(matches[0])
            baseline = Decimal(policy["baseline-percent"])
            if not Decimal("0") <= observed <= Decimal("100"):
                overall_pass = False
                coverage_validation_status = "FAIL"
                coverage_diagnostic = "observed coverage must be between 0 and 100"
                print(f"coverage-policy: {coverage_diagnostic}", file=sys.stderr)
            elif observed < baseline:
                overall_pass = False
                coverage_validation_status = "FAIL"
                coverage_diagnostic = (
                    f"coverage regression: observed {observed:.2f} "
                    f"< baseline {baseline:.2f}"
                )
                print(coverage_diagnostic, file=sys.stderr)
    else:
        print(
            "coverage-policy: non-applicable through "
            f"{policy['expiry']}; approver={policy['approver']}; reason={policy['reason']}"
        )

    for gate_name, display, status_text, arguments in gate_rows:
        if status_text != "AVAILABLE":
            overall_pass = False
            reason = display.removeprefix("reason=").strip()
            report_rows.append(
                ReportRow(gate_name, display, status_text, reason, None)
            )
            continue
        assert arguments is not None
        result = run_bounded(arguments, timeout_seconds)
        emit_safe(result.raw)
        if result.diagnostic:
            print(f"{gate_name}: {result.diagnostic}", file=sys.stderr)
        if result.code != 0:
            overall_pass = False
        report_rows.append(
            ReportRow(
                gate_name,
                display,
                str(result.code),
                result.report_output,
                result.digest,
            )
        )

    spec_arguments = (
        "bash",
        ".tdd-swarm/spec-lint.sh",
        ticket_argument,
        base_sha,
    )
    spec_display = (
        f"bash .tdd-swarm/spec-lint.sh {ticket_argument} {base_sha}"
    )
    spec_result = run_bounded(spec_arguments, timeout_seconds)
    emit_safe(spec_result.raw)
    if spec_result.diagnostic:
        print(f"spec-lint: {spec_result.diagnostic}", file=sys.stderr)
    if spec_result.code != 0:
        overall_pass = False
    report_rows.append(
        ReportRow(
            "spec-lint",
            spec_display,
            str(spec_result.code),
            spec_result.report_output,
            spec_result.digest,
        )
    )

    import_arguments = ("python3", ".tdd-swarm/check-import-cycles.py")
    import_display = "python3 .tdd-swarm/check-import-cycles.py"
    import_result = run_bounded(import_arguments, timeout_seconds)
    emit_safe(import_result.raw)
    if import_result.diagnostic:
        print(f"import-cycles: {import_result.diagnostic}", file=sys.stderr)
    if import_result.code != 0:
        overall_pass = False
    report_rows.append(
        ReportRow(
            "import-cycles",
            import_display,
            str(import_result.code),
            import_result.report_output,
            import_result.digest,
        )
    )
    import_matches = re.findall(
        rb"sha256=([0-9a-f]{64})",
        import_result.raw,
    )
    import_hash = (
        import_matches[0].decode("ascii")
        if import_result.code == 0 and len(import_matches) == 1
        else "unavailable"
    )

    current_head = git(["rev-parse", "--verify", "HEAD^{commit}"])
    if current_head.returncode != 0 or current_head.stdout.strip() != head_sha:
        fatal("HEAD changed while gate commands were executing")
    revalidate_inputs(all_input_snapshots)

    hashes = {
        "coverage-policy-sha256": policy_snapshot.digest,
        "import-graph-sha256": import_hash,
        "ticket-sha256": ticket_snapshot.digest,
        "gate-map-sha256": gate_map_snapshot.digest,
        "wrapper-sha256": core_snapshots[".tdd-swarm/run-local-gates.sh"].digest,
        "publisher-sha256": core_snapshots[".tdd-swarm/publish-report.py"].digest,
        "spec-lint-sha256": core_snapshots[".tdd-swarm/spec-lint.sh"].digest,
        "import-cycle-tool-sha256": core_snapshots[
            ".tdd-swarm/check-import-cycles.py"
        ].digest,
        "test-scope-sha256": aggregate_scope_hash(test_scope_snapshots),
    }
    report_lines = [
        f"# Local gate report — {ticket_id}",
        "",
        f"ticket: {ticket_argument}",
        f"base: {base_sha}",
        f"head: {head_sha}",
        *(f"{label}: {value}" for label, value in hashes.items()),
        f"coverage-decision: {policy['decision']}",
        f"coverage-validation-status: {coverage_validation_status}",
    ]
    if coverage_diagnostic:
        report_lines.append(f"coverage-validation-diagnostic: {coverage_diagnostic}")
    if policy["decision"] == "non-applicable":
        report_lines.extend(
            [
                f"coverage-reason: {policy['reason']}",
                f"coverage-approver: {policy['approver']}",
                f"coverage-date: {policy['date']}",
                f"coverage-expiry: {policy['expiry']}",
            ]
        )
    else:
        report_lines.extend(
            [
                f"coverage-baseline-base-sha: {base_sha}",
                f"coverage-baseline-percent: {policy['baseline-percent']}",
            ]
        )
    report_lines.extend(
        [
            "",
            "| gate | exact command | exit | output |",
            "|---|---|---:|---|",
        ]
    )
    for row in report_rows:
        report_lines.append(
            f"| {row.gate} | `{row.command}` | {row.exit_value} | {row.output} |"
        )
        if row.digest is not None:
            report_lines.append(f"output-sha256: {row.digest}")
    report_lines.extend(
        [
            "",
            f"overall-verdict: {'PASS' if overall_pass else 'FAIL'}",
            "",
        ]
    )
    report_bytes = "\n".join(report_lines).encode("utf-8")
    staged, destination = stage_report(ticket_id, report_bytes)
    wait_failpoint("before-report-publish")
    latest_head = git(["rev-parse", "--verify", "HEAD^{commit}"])
    if latest_head.returncode != 0 or latest_head.stdout.strip() != head_sha:
        fatal("HEAD changed before report publication")
    revalidate_inputs(all_input_snapshots)

    publisher_arguments = (
        "python3",
        ".tdd-swarm/publish-report.py",
        str(staged),
        str(destination),
    )
    publisher_result = run_bounded(
        publisher_arguments,
        max(timeout_seconds, 2.0),
    )
    emit_safe(publisher_result.raw)
    if publisher_result.diagnostic:
        print(f"report publisher: {publisher_result.diagnostic}", file=sys.stderr)
    if publisher_result.code != 0:
        return publisher_result.code
    print(f"local-gates: report=.tdd-swarm/reports/{ticket_id}-gates.md")
    return 0 if overall_pass else 1


try:
    raise SystemExit(main())
except FatalGateError as exc:
    print(f"local-gates: {exc}", file=sys.stderr)
    raise SystemExit(exc.status)
PY
