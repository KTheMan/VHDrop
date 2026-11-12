#!/usr/bin/env python3
"""Create only the share's protected coordination directories.

This small program is designed to be supplied from a trusted local bundle over
stdin to ``sudo -n python3 - /absolute/canonical/share``. Do not execute a
user-writable remote script with sudo. It accepts no shell commands or secrets.
"""
import os
import stat
import sys


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0:
        raise ValueError('Expected one share root and root privileges')
    root = sys.argv[1]
    if (not root or root == '/' or not os.path.isabs(root) or os.path.realpath(root) != root
            or any(c in root for c in ('\x00', '\n', '\r'))):
        raise ValueError('Share root must be canonical, absolute and not /')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    # Walk from / using directory descriptors, so a writable/replaced ancestor
    # cannot redirect privileged mkdir into an unintended location.
    fd = os.open('/', flags)
    try:
        for part in root.strip('/').split('/'):
            child = os.open(part, flags, dir_fd=fd)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                os.close(child)
                raise ValueError('Every share ancestor must be root-owned and non-writable')
            os.close(fd)
            fd = child
        initial = os.fstat(fd)
        named = os.lstat(root)
        if ((initial.st_dev, initial.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISDIR(initial.st_mode) or initial.st_uid != 0 or initial.st_mode & 0o022):
            raise ValueError('Share root must be a safely owned, non-writable directory')
        for name in ('.vhdx-handoff', 'operations'):
            try:
                os.mkdir(name, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, flags, dir_fd=fd)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or info.st_dev != initial.st_dev):
                os.close(child)
                raise ValueError('Unsafe coordination directory; nothing was overwritten')
            os.close(fd)
            fd = child
    finally:
        os.close(fd)
    print('VHDX_HANDOFF_ROOT_READY')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print('VHDX_HANDOFF_ROOT_ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
