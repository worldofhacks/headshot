#!/usr/bin/env python3
"""Fixed atomic publication boundary for a prepared local-gate report."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def publish_report(staged: Path, destination: Path) -> None:
    """Atomically replace ``destination`` with the prepared same-directory stage."""
    staged = Path(staged)
    destination = Path(destination)
    if staged.name in {"", ".", ".."} or destination.name in {"", ".", ".."}:
        raise ValueError("report paths require safe leaf names")
    if staged.name == destination.name:
        raise ValueError("staged report and destination must be distinct")
    if staged.parent.absolute() != destination.parent.absolute():
        raise ValueError("staged report and destination must share a directory")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(staged.parent, directory_flags)
    try:
        stage_status = os.stat(staged.name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(stage_status.st_mode):
            raise ValueError("staged report must be a regular non-symlink file")
        try:
            destination_status = os.stat(
                destination.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            destination_status = None
        if destination_status is not None and not stat.S_ISREG(destination_status.st_mode):
            raise ValueError("report destination must be a regular non-symlink file")

        stage_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            stage_flags |= os.O_NOFOLLOW
        stage_fd = os.open(staged.name, stage_flags, dir_fd=directory_fd)
        try:
            descriptor_status = os.fstat(stage_fd)
            if (
                descriptor_status.st_dev != stage_status.st_dev
                or descriptor_status.st_ino != stage_status.st_ino
                or not stat.S_ISREG(descriptor_status.st_mode)
            ):
                raise ValueError("staged report changed before publication")
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)

        os.replace(
            staged.name,
            destination.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <staged-report> <destination>", file=sys.stderr)
        return 2
    publish_report(Path(argv[1]), Path(argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
