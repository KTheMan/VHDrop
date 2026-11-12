"""Load the explicitly provisioned, root-owned guest-SMB guard configuration.

This is a topology-specific guard for co-located Samba or a Proxmox LXC. No environment variables or per-request
arguments may override the root-controlled mapping or enable a weaker guard.
"""
from __future__ import annotations
import json
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

CONFIG_PATH = Path('/etc/vhdx-handoff-v1/guard.json')


def _absolute_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith('/') or value == '/':
        raise ValueError(label + ' must be an absolute non-root path')
    if any(ch in value for ch in ('\x00', '\n', '\r', '\\')) or str(PurePosixPath(value)) != value:
        raise ValueError(label + ' must be normalized without backslashes')
    if any(part in ('.', '..') for part in value.split('/')):
        raise ValueError(label + ' cannot contain traversal')
    return value


def parse(data: object) -> dict:
    required = {'local_root', 'guest_root', 'smb_host', 'smb_share', 'container_id', 'guest_username', 'guest_smb_acknowledged'}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError('Guard configuration must contain exactly the documented fields')
    local = _absolute_path(data['local_root'], 'local_root')
    guest = _absolute_path(data['guest_root'], 'guest_root')
    if not isinstance(data['smb_host'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', data['smb_host']):
        raise ValueError('smb_host must be an IPv4 address or DNS hostname')
    if not isinstance(data['smb_share'], str) or not re.fullmatch(r'[A-Za-z0-9_. -]{1,80}', data['smb_share']):
        raise ValueError('smb_share contains unsupported characters')
    if not isinstance(data['container_id'], str) or (data['container_id'] and not re.fullmatch(r'[0-9]{1,12}', data['container_id'])):
        raise ValueError('container_id must be empty for local Samba or a numeric Proxmox LXC ID')
    if not data['container_id'] and local != guest:
        raise ValueError('Co-located Samba requires identical host and Samba share paths')
    if not isinstance(data['guest_username'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', data['guest_username']):
        raise ValueError('guest_username contains unsupported characters')
    if data['guest_smb_acknowledged'] is not True:
        raise ValueError('Guest SMB must be explicitly acknowledged')
    if not os.path.isdir(local) or os.path.realpath(local) != local:
        raise ValueError('local_root must be an existing canonical directory')
    return {'local_root': local, 'guest_root': guest, 'smb_host': data['smb_host'],
            'smb_share': data['smb_share'], 'container_id': data['container_id'], 'guest_username': data['guest_username'],
            'guest_smb_acknowledged': True}


def load_with_digest(path: Path = CONFIG_PATH, expected_owner: int = 0) -> tuple[dict, str]:
    path = Path(path)
    parent = path.parent
    if not path.is_absolute() or os.path.realpath(parent) != str(parent):
        raise ValueError('Guard config directory must be an absolute non-symlink path')
    for directory in (parent, *parent.parents):
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_owner or info.st_mode & 0o022:
            raise ValueError('Guard config directory is not trusted: ' + str(directory))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner or info.st_mode & 0o022:
            raise ValueError('Guard config is not root-owned and protected')
        if info.st_size > 65536:
            raise ValueError('Guard config is unexpectedly large')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('Guard config is unexpectedly large')
        return parse(json.loads(raw.decode('utf-8'))), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)


def load(path: Path = CONFIG_PATH, expected_owner: int = 0) -> dict:
    return load_with_digest(path, expected_owner)[0]
