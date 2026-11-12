#!/usr/bin/env python3
"""Install/check the per-user read-only VHDX copy helper on a Linux share host.

Prepare the coordination directories using the separate trusted marker-only
program, and run ``--install`` as the SSH user. No SSH credentials are stored.
Only --install accesses the package index.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

TARGET_VERSION = '3.25.1'
HELPER_SHA256 = 'fd74a414c22581a5b7b56d9c3b4634cb034c87d41972046b6b4b0eb63dc94fce'
def runtime_name() -> str:
    major, minor = sys.version_info[:2]
    if major != 3 or not 10 <= minor <= 13:
        raise ValueError('Copy helper requires system Python 3.10 through 3.13')
    return f'venv-{major}.{minor}'


def launcher_text(name: str) -> str:
    return ('#!/bin/sh\nexec "$HOME/.local/share/vhdx-handoff/' + name + '/bin/python" '
            '"$HOME/.local/share/vhdx-handoff/lib/vhdx-copy.py" "$@"\n')


def checker_text(name: str) -> str:
    return ('#!/bin/sh\nexec "$HOME/.local/share/vhdx-handoff/' + name + '/bin/python" '
            '"$HOME/.local/share/vhdx-handoff/lib/setup_copy.py" --check --root "$1"\n')


def canonical_root(value: str) -> Path:
    if not value or any(c in value for c in ('\x00', '\n', '\r')):
        raise ValueError('Invalid share root')
    if not os.path.isabs(value) or os.path.realpath(value) != value or value == '/':
        raise ValueError('Share root must be an existing canonical absolute directory, not /')
    path = Path(value)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Share root must be a root-owned, non-writable directory')
    return path


def marker_check(root: Path, create: bool = False) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open('/', flags)
    try:
        for name in str(root).strip('/').split('/'):
            child = os.open(name, flags, dir_fd=fd)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                os.close(child)
                raise ValueError('Every share ancestor must be root-owned and non-writable')
            os.close(fd)
            fd = child
        root_stat = os.fstat(fd)
        for name in ('.vhdx-handoff', 'operations'):
            if create:
                try:
                    os.mkdir(name, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(name, flags, dir_fd=fd)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                os.close(child)
                raise ValueError('Coordination directory must be root-owned and non-writable')
            if info.st_dev != root_stat.st_dev:
                os.close(child)
                raise ValueError('Coordination directory must be on the share filesystem')
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def install_dir() -> Path:
    return Path.home() / '.local' / 'share' / 'vhdx-handoff'


def protected_bytes(path: Path, limit: int = 1024 * 1024) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Installed helper file has unsafe ownership or permissions: ' + str(path))
        if info.st_size > limit:
            raise ValueError('Installed helper file is unexpectedly large: ' + str(path))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)


def ensure_owned_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Installation directory is not safely owned: ' + str(path))


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Replace a named file, never follow an existing destination symlink."""
    fd, temporary = tempfile.mkstemp(prefix='.vhdx-handoff-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def check(root: Path) -> None:
    marker_check(root)
    dest = install_dir()
    config_path = dest / 'config.json'
    config = json.loads(protected_bytes(config_path, 16384).decode('utf-8'))
    if config != {'share_root': str(root)}:
        raise ValueError('Installed copy-helper share root does not match this setup')
    script = dest / 'lib' / 'vhdx-copy.py'
    launcher = dest / 'bin' / 'vhdx-copy'
    installed_setup = dest / 'lib' / 'setup_copy.py'
    checker = dest / 'bin' / 'vhdx-handoff-check'
    name = runtime_name()
    python = dest / name / 'bin' / 'python'
    for path in (script, launcher, installed_setup, checker, python):
        if not path.exists(): raise ValueError(f'Missing installed file: {path}')
    if not os.access(launcher, os.X_OK) or not os.access(python, os.X_OK):
        raise ValueError('Installed copy helper or interpreter is not executable')
    if hashlib.sha256(protected_bytes(script)).hexdigest() != HELPER_SHA256:
        raise ValueError('Installed copy helper does not match this application version; reinstall it')
    if protected_bytes(launcher) != launcher_text(name).encode('utf-8'):
        raise ValueError('Installed copy launcher has unexpected contents; reinstall it')
    result = subprocess.run([str(python), '-c',
        'import importlib.metadata; import dissect.target; '
        'assert importlib.metadata.version("dissect.target") == "' + TARGET_VERSION + '"'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    if result.returncode:
        raise ValueError('Required Dissect runtime is unavailable or mismatched')


def install(root: Path) -> None:
    name = runtime_name()
    marker_check(root)
    source = Path(__file__).resolve().with_name('vhdx-copy')
    if not source.is_file(): raise ValueError('vhdx-copy must be next to setup_copy.py')
    if hashlib.sha256(source.read_bytes()).hexdigest() != HELPER_SHA256:
        raise ValueError('The bundled copy helper does not match the setup program')
    dest = install_dir()
    ensure_owned_dir(dest)
    for directory in ('lib', 'bin'):
        ensure_owned_dir(dest / directory)
    venv = dest / name
    if venv.is_symlink(): raise ValueError('Virtual environment cannot be a symbolic link')
    if venv.exists(): ensure_owned_dir(venv)
    subprocess.run([sys.executable, '-m', 'venv', str(venv)], check=True)
    python = venv / 'bin' / 'python'
    subprocess.run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check',
                    'dissect.target==' + TARGET_VERSION], check=True)
    atomic_write(dest / 'lib' / 'vhdx-copy.py', source.read_bytes(), 0o600)
    atomic_write(dest / 'lib' / 'setup_copy.py', Path(__file__).resolve().read_bytes(), 0o600)
    atomic_write(dest / 'config.json', (json.dumps({'share_root': str(root)}) + '\n').encode('utf-8'), 0o600)
    launcher = dest / 'bin' / 'vhdx-copy'
    atomic_write(launcher, launcher_text(name).encode('utf-8'), 0o700)
    checker = dest / 'bin' / 'vhdx-handoff-check'
    atomic_write(checker, checker_text(name).encode('utf-8'), 0o700)
    check(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--install', action='store_true')
    group.add_argument('--check', action='store_true')
    parser.add_argument('--root', required=True, help='Canonical absolute Linux share root')
    args = parser.parse_args()
    try:
        root = canonical_root(args.root)
        if args.install:
            install(root)
            print('VHDX_HANDOFF_COPY_READY')
        else:
            check(root)
            print('VHDX_HANDOFF_COPY_READY')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print('VHDX_HANDOFF_SETUP_ERROR: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
