"""Secret-isolated, resource-bounded subprocess execution for pinned scanners."""

from __future__ import annotations

import os
import resource
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

_ALLOWED_ENV_KEYS = frozenset({"LANG", "LC_ALL", "NO_COLOR", "PATH", "PYTHONPATH"})


class ToolProcessError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ToolProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _limits(cpu_seconds: int, memory_bytes: int, output_bytes: int):
    def apply() -> None:
        # Darwin rejects some otherwise valid address-space limits in a pre-exec child; Linux
        # applies all four. A platform-specific unsupported limit must not turn into an opaque
        # Popen error, while the remaining supported limits still apply.
        for resource_kind, limit in (
            (resource.RLIMIT_CPU, cpu_seconds),
            (resource.RLIMIT_AS, memory_bytes),
            (resource.RLIMIT_FSIZE, output_bytes),
            (resource.RLIMIT_NOFILE, 64),
        ):
            try:
                resource.setrlimit(resource_kind, (limit, limit))
            except (OSError, ValueError):
                continue

    return apply


def run_bounded_tool(
    argv: Sequence[str],
    *,
    cwd: Path,
    allowed_env: Mapping[str, str] | None = None,
    timeout_s: float = 120,
    max_output_bytes: int = 10 * 1024 * 1024,
    cpu_seconds: int = 120,
    memory_bytes: int = 2 * 1024 * 1024 * 1024,
) -> ToolProcessResult:
    """Run an argument array with no shell and no inherited credentials.

    Only explicitly allowed non-secret environment keys cross the boundary. HOME and temporary
    paths point to a fresh directory, while CPU, address space, file size, descriptor count,
    wall time, and captured output are bounded.
    """
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise ValueError("tool argv must contain non-empty strings")
    if timeout_s <= 0 or max_output_bytes <= 0 or cpu_seconds <= 0 or memory_bytes <= 0:
        raise ValueError("tool resource limits must be positive")
    cwd = cwd.resolve(strict=True)
    supplied = dict(allowed_env or {})
    forbidden = sorted(set(supplied) - _ALLOWED_ENV_KEYS)
    if forbidden:
        raise ValueError(f"tool environment key is not allowed: {forbidden[0]}")

    with tempfile.TemporaryDirectory(prefix="agentforge-tool-") as temporary_home:
        environment = {
            "HOME": temporary_home,
            "TMPDIR": temporary_home,
            "LANG": supplied.pop("LANG", "C.UTF-8"),
            "LC_ALL": supplied.pop("LC_ALL", "C.UTF-8"),
            "NO_COLOR": supplied.pop("NO_COLOR", "1"),
            "PATH": supplied.pop("PATH", os.defpath),
            **supplied,
        }
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            preexec_fn=_limits(cpu_seconds, memory_bytes, max_output_bytes),
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate()
            raise ToolProcessError("timeout", "tool exceeded its configured deadline") from exc
        if len(stdout) + len(stderr) > max_output_bytes:
            raise ToolProcessError("output_limit", "tool exceeded its captured output limit")
        return ToolProcessResult(process.returncode, stdout, stderr)
