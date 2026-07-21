"""Private scheduler process that may enqueue stored schedules but never execute attacks."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any


class SchedulerUnavailable(RuntimeError):
    """No authoritative schedule repository/queue composition exists."""


def enqueue_due_work(*, schedule_repository: Any, queue: Any) -> int:
    """Enqueue persisted due work only; never construct an adapter or execute inline."""

    if schedule_repository is None or queue is None:
        raise SchedulerUnavailable("authoritative_schedule_repository_missing")
    due = schedule_repository.claim_due()
    count = 0
    for schedule in due:
        queue.enqueue_schedule(schedule)
        schedule_repository.mark_enqueued(schedule)
        count += 1
    return count


def check_runtime(database_url: str | None = None) -> bool:
    url = database_url if database_url is not None else os.environ.get("DATABASE_URL")
    return bool(url) and os.environ.get("AGENTFORGE_SCHEDULER_READY") == "true"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge-scheduler")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    ready = check_runtime()
    if args.check:
        return 0 if ready else 1
    if not ready:
        print("scheduler unavailable: authoritative schedule repository is absent", file=sys.stderr)
        return 1
    print("scheduler unavailable: no schedule/queue composition is installed", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["SchedulerUnavailable", "check_runtime", "enqueue_due_work", "main"]
