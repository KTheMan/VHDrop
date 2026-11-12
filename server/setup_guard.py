#!/usr/bin/env python3
"""Install/check the restricted co-located Samba or Proxmox/LXC guest-SMB deletion guard.

Run this exact trusted code as root, not a user-writable remote file. ``--install``
reads a bounded JSON request from stdin with ``config`` and base64 ``files``.
It refuses to overwrite an existing helper or guard configuration. ``--check``
requires an actual detached image and validates SMB/host/guest inode identity.
This guard supports only the explicitly acknowledged guest-SMB topology.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

INSTALL = Path('/opt/vhdx-handoff-v1')
CONFIG = Path('/etc/vhdx-handoff-v1')
EXPECTED = {
 'vhdx_delete.py': '9e0452d818693ead1ed9de324e9d0392e535e70ee28bba6a80934e2b59822346',
 'delete_inside_mount.py': '8519e7245921d5a6318f6963f5ba03e941d658f48a703753c06fb6790b4e3d86',
 'operation_state.py': '1c61c37ecc0d8339136f28918234b6efb9e9dd1806679c60eabc6fef82a99321',
 'smb_guard.py': 'f80f427815e8a74acd9b49947fde3d07e81eec3e5311658b430631d21e5002d0',
 'host_config.py': '9bf85980a07ae6b5f901de483838f7ec401a38696756956c6fc7ffd1c0419e11',
 'pyspnego-0.12.4-py3-none-any.whl': 'a29a34de1abe9e9b30d9aa1d363f8e49fc159eb7355b1f2ee86ccb3a2ce3bba9',
 'smbprotocol-1.17.0-py3-none-any.whl': 'bd1abff5417f5af83ca516a64ab8e5acece3dbdcf58d4e5e23e47f5165a77349',
}
COMMANDS = ('qemu-img','qemu-nbd','ntfs-3g','ntfs-3g.probe','ntfsinfo','ntfsls',
            'blkid','modprobe','mount','umount','fuser','sync')


def digest(data): return hashlib.sha256(data).hexdigest()


def dependencies(config=None):
    missing = [name for name in COMMANDS if shutil.which(name) is None]
    if config is not None:
        extra = ('pct',) if config['container_id'] else ('testparm', 'stat')
        missing.extend(name for name in extra if shutil.which(name) is None)
    if missing: raise ValueError('Missing host commands: ' + ', '.join(missing))
    subprocess.run(['/usr/bin/python3','-I','-c','import cryptography'], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=20)


def validate_payload(request):
    if not isinstance(request, dict) or set(request) != {'config', 'files'}:
        raise ValueError('Expected exactly config and files')
    files = request['files']
    if not isinstance(files, dict) or set(files) != set(EXPECTED):
        raise ValueError('Guard bundle files do not match the expected version')
    decoded = {}
    for name, expected in EXPECTED.items():
        value = files[name]
        if not isinstance(value, str) or len(value) > 4_000_000:
            raise ValueError('Invalid guard bundle file')
        decoded[name] = base64.b64decode(value, validate=True)
        if digest(decoded[name]) != expected:
            raise ValueError('Guard bundle file integrity mismatch: ' + name)
    namespace = {'__name__': 'trusted_guard_config'}
    exec(compile(decoded['host_config.py'], '<verified-host-config>', 'exec'), namespace)
    config = namespace['parse'](request['config'])
    return config, decoded


def extract_wheel(wheel, vendor):
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        if len(archive.infolist()) > 3000: raise ValueError('Wheel has too many entries')
        total = 0
        for item in archive.infolist():
            p = PurePosixPath(item.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in item.filename:
                raise ValueError('Unsafe wheel entry')
            if stat.S_ISLNK(item.external_attr >> 16): raise ValueError('Wheel links are not allowed')
            total += item.file_size
            if total > 20_000_000: raise ValueError('Wheel is unexpectedly large')
            target = vendor.joinpath(*p.parts)
            if item.is_dir(): target.mkdir(parents=True, exist_ok=True); continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists(): raise ValueError('Conflicting wheel files')
            with target.open('xb') as stream: stream.write(archive.read(item))
            target.chmod(0o644)


def install(request):
    config, files = validate_payload(request)
    dependencies(config)
    if INSTALL.exists() or INSTALL.is_symlink() or CONFIG.exists() or CONFIG.is_symlink():
        raise ValueError('Existing helper/configuration not overwritten; inspect it before any upgrade')
    # /opt and /etc are root-owned standard parents. Refuse unsafe replacements.
    for parent in (INSTALL.parent, CONFIG.parent):
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe installation parent: ' + str(parent))
    install_stage = Path(tempfile.mkdtemp(prefix='.vhdx-handoff-', dir=INSTALL.parent))
    config_stage = Path(tempfile.mkdtemp(prefix='.vhdx-handoff-', dir=CONFIG.parent))
    try:
        install_stage.chmod(0o755); config_stage.chmod(0o700)
        for name in EXPECTED:
            if name.endswith('.py'):
                target = install_stage / name
                target.write_bytes(files[name]); target.chmod(0o755 if name == 'vhdx_delete.py' else 0o644)
        vendor = install_stage / 'vendor'; vendor.mkdir(mode=0o755)
        for name in EXPECTED:
            if name.endswith('.whl'): extract_wheel(files[name], vendor)
        guard_config = config_stage / 'guard.json'
        guard_config.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8'); guard_config.chmod(0o600)
        # Root-only parents prevent unprivileged replacement between checks and rename.
        if INSTALL.exists() or CONFIG.exists(): raise ValueError('Installation target appeared; refusing overwrite')
        os.rename(config_stage, CONFIG)
        try: os.rename(install_stage, INSTALL)
        except BaseException as exc:
            raise RuntimeError('Config installed but helper install failed; inspect ' + str(CONFIG)) from exc
        print('VHDX_HANDOFF_GUARD_INSTALLED')
    finally:
        for stage, parent in ((install_stage, INSTALL.parent), (config_stage, CONFIG.parent)):
            if stage.exists() and stage.parent == parent and stage.name.startswith('.vhdx-handoff-'):
                shutil.rmtree(stage)


def check(image, expected_digest):
    dependencies()
    for name, expected in EXPECTED.items():
        if not name.endswith('.py'): continue
        path = INSTALL / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os,'O_CLOEXEC',0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Untrusted installed guard file: ' + name)
            with os.fdopen(os.dup(fd),'rb') as stream:
                if digest(stream.read()) != expected: raise ValueError('Installed guard version mismatch: ' + name)
        finally: os.close(fd)
    result = subprocess.run(['/usr/bin/python3','-I',str(INSTALL/'vhdx_delete.py'),'--status',
                             '--expected-config-digest',expected_digest,'--',image],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=90)
    if result.returncode or not result.stdout.startswith('CLEAR:'):
        raise ValueError('Guard status failed: ' + (result.stderr.strip() or 'no clear response'))
    print('VHDX_HANDOFF_GUARD_READY')


def main():
    # Root subprocess lookup must never use a caller-controlled PATH.
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--install',action='store_true')
    group.add_argument('--check',action='store_true')
    parser.add_argument('--image')
    parser.add_argument('--expected-config-digest')
    args=parser.parse_args()
    if os.geteuid()!=0: raise ValueError('The guard installer/check requires root')
    if args.install:
        if args.image or args.expected_config_digest: raise ValueError('Image and digest are only valid for --check')
        raw=sys.stdin.buffer.read(8_000_001)
        if len(raw)>8_000_000: raise ValueError('Guard bundle is too large')
        install(json.loads(raw))
    else:
        if not args.image or not args.expected_config_digest:
            raise ValueError('--check requires a detached image and expected guard config digest')
        check(args.image, args.expected_config_digest)


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print('VHDX_HANDOFF_GUARD_ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
