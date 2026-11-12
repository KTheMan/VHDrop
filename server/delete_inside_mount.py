#!/usr/bin/env python3
"""Remove an item relative to a privately mounted VHDX filesystem.

Usage: delete_inside_mount.py MOUNT_ROOT RELATIVE_PATH file|dir

The caller MUST first establish exclusive access to the detached VHDX, mount it
in a private namespace without nested mounts, and prevent concurrent writers.
This primitive does not check attachment state or mount/unmount anything. It
rejects a root target, traversal, alternate streams, symlink ancestors/targets,
and type changes. A selected directory is removed recursively; links inside it
are unlinked, never followed. There is no trash or recovery facility.
"""
from __future__ import annotations

import argparse
import contextlib
import inspect
import os
import shutil
import stat
import sys


class DeleteError(Exception):
    """The requested item could not be safely removed."""


def _components(relative_path: str) -> list[str]:
    if not relative_path or relative_path[0] in "/\\":
        raise DeleteError("Select a file or folder below the volume root")
    if any(ord(c) < 32 or ord(c) == 127 for c in relative_path) or ":" in relative_path:
        raise DeleteError("Control characters and alternate streams are not allowed")
    # Windows paths from the picker use backslashes, while the mount uses '/'.
    parts = relative_path.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise DeleteError("Empty and traversal path components are not allowed")
    return parts


def _identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def delete_inside_mount(mount_root: str, relative_path: str, expected: str, before_mutation=None) -> None:
    """Remove one selected regular file or directory beneath the mount root.

    Directory removal requires Python's fd-based symlink-resistant rmtree. The
    operation is irreversible. See module docstring for caller requirements.
    """
    parts = _components(relative_path)
    if expected not in ("file", "dir"):
        raise DeleteError("Expected type must be file or dir")
    if not os.path.isabs(mount_root):
        raise DeleteError("Mount root must be an absolute path")
    mount_root = os.path.normpath(mount_root)
    if os.path.realpath(mount_root) == os.path.sep:
        raise DeleteError("The system root cannot be used as a VHDX mount")
    if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise DeleteError("This platform cannot securely traverse directories")
    if not all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.unlink)):
        raise DeleteError("This platform lacks required fd-relative operations")
    if expected == "dir" and (not getattr(shutil.rmtree, "avoids_symlink_attacks", False) or "dir_fd" not in inspect.signature(shutil.rmtree).parameters):
        raise DeleteError("This Python cannot safely remove directory trees")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    target_flags = getattr(os, "O_PATH", os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    try:
        root_fd = os.open(mount_root, directory_flags)
        descriptors.append(root_fd)
        root_device = os.fstat(root_fd).st_dev
        parent_fd = root_fd
        for part in parts[:-1]:
            parent_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            descriptors.append(parent_fd)
            if os.fstat(parent_fd).st_dev != root_device:
                raise DeleteError("Crossing filesystem boundaries is not allowed")

        name = parts[-1]
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if observed.st_dev != root_device:
            raise DeleteError("Crossing filesystem boundaries is not allowed")
        if stat.S_ISLNK(observed.st_mode):
            raise DeleteError("Symbolic links and reparse points cannot be selected")
        if expected == "file" and not stat.S_ISREG(observed.st_mode):
            raise DeleteError("The item is not a regular file")
        if expected == "dir" and not stat.S_ISDIR(observed.st_mode):
            raise DeleteError("The item is not a directory")

        # Revalidate the opened item against its directory entry before deletion.
        # The surrounding private mount and exclusive-access protocol are still
        # required: POSIX unlink-by-name cannot eliminate every concurrent race.
        target_fd = os.open(name, target_flags, dir_fd=parent_fd)
        descriptors.append(target_fd)
        opened = os.fstat(target_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(observed) != _identity(opened) or _identity(opened) != _identity(current):
            raise DeleteError("The selected item changed; inspect it again")
        if expected == "file":
            if before_mutation is not None:
                before_mutation()
            os.unlink(name, dir_fd=parent_fd)
        else:
            # CPython verifies the opened directory and traverses fd-relative;
            # wrap each unlink/rmdir so an orchestrator can recheck its live
            # share-deny lease immediately before every irreversible operation.
            original_unlink, original_rmdir = os.unlink, os.rmdir
            def guarded_unlink(*args, **kwargs):
                if before_mutation is not None:
                    before_mutation()
                return original_unlink(*args, **kwargs)
            def guarded_rmdir(*args, **kwargs):
                if before_mutation is not None:
                    before_mutation()
                return original_rmdir(*args, **kwargs)
            try:
                os.unlink, os.rmdir = guarded_unlink, guarded_rmdir
                shutil.rmtree(name, dir_fd=parent_fd)
            finally:
                os.unlink, os.rmdir = original_unlink, original_rmdir
    except OSError as e:
        raise DeleteError(f"Could not safely remove the selected {expected}: {e}") from e
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-request-fd", type=int, required=True)
    parser.add_argument("--guard-response-fd", type=int, required=True)
    parser.add_argument("mount_root")
    parser.add_argument("relative_path")
    parser.add_argument("expected", choices=("file", "dir"))
    args = parser.parse_args(argv)
    try:
        def request_guard():
            try:
                os.write(args.guard_request_fd, b"G")
                if os.read(args.guard_response_fd, 1) != b"Y":
                    raise DeleteError("Exclusive image guard is not available")
            except OSError as exc:
                raise DeleteError(f"Exclusive image guard communication failed: {exc}") from exc
        delete_inside_mount(args.mount_root, args.relative_path, args.expected, request_guard)
    except DeleteError as e:
        print(str(e), file=sys.stderr)
        return 1
    print(f"Deleted {args.expected}: {args.relative_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





