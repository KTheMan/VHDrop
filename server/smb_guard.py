"""Verified exclusive SMB guard for detached VHDX operations on a Linux host.

This guards SMB opens, not uncooperative local POSIX writers. The explicitly
configured guest SMB share must be on a trusted network. A guard query is a
point-in-time check, not proof of uninterrupted
exclusivity during network failure; callers must treat every failure as fatal and
keep the context open through unmount and NBD disconnect.

Runtime: smbprotocol==1.17.0 and pyspnego==0.12.4 in an isolated Python env.
"""
from contextlib import contextmanager
import os
import secrets
import sys
import importlib.metadata
from pathlib import Path, PurePosixPath
import stat
import subprocess

LOCAL_ROOT = None
GUEST_ROOT = None
SMB_HOST = None
SMB_ROOT = None
SMB_SHARE = None
GUEST_USERNAME = None
CONTAINER_ID = None


def configure(config):
    """Set only values already validated from the root-owned guard config."""
    global LOCAL_ROOT, GUEST_ROOT, SMB_HOST, SMB_ROOT, SMB_SHARE, CONTAINER_ID, GUEST_USERNAME
    LOCAL_ROOT = Path(config['local_root'])
    GUEST_ROOT = PurePosixPath(config['guest_root'])
    SMB_HOST = config['smb_host']
    SMB_SHARE = config['smb_share']
    SMB_ROOT = '\\\\' + SMB_HOST + '\\' + SMB_SHARE
    CONTAINER_ID = config['container_id']
    GUEST_USERNAME = config['guest_username']


def _checked_local(path):
    """Open the exact local file, refusing relative, traversal, links and mounts."""
    if LOCAL_ROOT is None:
        raise RuntimeError('Guard is not configured; deletion is unavailable')
    raw = os.fspath(path)
    if not isinstance(raw, str) or any(c in raw for c in ('\x00','\n','\r','\\')):
        raise ValueError('Invalid image path')
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise ValueError('Image path must be absolute and normalized')
    p = Path(raw)
    try:
        relative = p.relative_to(LOCAL_ROOT)
    except ValueError as e:
        raise ValueError('Image must be inside the configured share') from e
    if not relative.parts or p.suffix.lower() != '.vhdx':
        raise ValueError('Select a VHDX file inside the configured share')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    dir_flags = flags | getattr(os, 'O_DIRECTORY', 0)
    root_fd = os.open('/', dir_flags)
    try:
        for part in LOCAL_ROOT.parts[1:]:
            nxt = os.open(part, dir_flags, dir_fd=root_fd)
            root_info = os.fstat(nxt)
            if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_mode & 0o022:
                os.close(nxt)
                raise ValueError('Share ancestor is unsafe or not root-owned')
            os.close(root_fd)
            root_fd = nxt
    except BaseException:
        os.close(root_fd)
        raise
    current = root_fd
    try:
        root_stat = os.fstat(root_fd)
        for part in relative.parts[:-1]:
            nxt = os.open(part, dir_flags, dir_fd=current)
            if os.fstat(nxt).st_dev != root_stat.st_dev:
                os.close(nxt)
                raise ValueError('Image path crosses a filesystem boundary')
            if current != root_fd: os.close(current)
            current = nxt
        fd = os.open(relative.name, flags, dir_fd=current)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_dev != root_stat.st_dev:
                raise ValueError('Image is not a regular file on the share filesystem')
            entry = os.stat(relative.name, dir_fd=current, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Image path changed during validation')
            return fd, current, root_fd, relative, root_stat, info
        except BaseException:
            os.close(fd)
            raise
    except BaseException:
        if current != root_fd: os.close(current)
        os.close(root_fd)
        raise


def _pct(*args):
    # Empty container ID selects Samba co-located on this exact host. Never
    # infer a remote mapping from path names alone. PATH is fixed by caller.
    command = ['pct','exec',CONTAINER_ID,'--',*args] if CONTAINER_ID else list(args)
    result = subprocess.run(command,
                            capture_output=True,text=True,timeout=12,check=False)
    if result.returncode != 0:
        raise RuntimeError('Could not verify guest share mapping: ' + result.stderr.strip())
    return result.stdout.strip()


def _mapping_check(relative, info):
    # Check the current Samba configuration and the mounted guest view, then
    # compare Linux device and inode. Do not infer the mapping from paths alone.
    if GUEST_ROOT is None or SMB_SHARE is None or CONTAINER_ID is None:
        raise RuntimeError('Guard is not configured; deletion is unavailable')
    share_path = _pct('testparm','-s','--section-name=' + SMB_SHARE,'--parameter-name=path')
    if share_path.rstrip('/') != str(GUEST_ROOT):
        raise RuntimeError('Samba share path changed; refusing write access')
    guest = str(GUEST_ROOT.joinpath(*relative.parts))
    guest_id = _pct('stat','-c','%d:%i','--',guest)
    if guest_id != f'{info.st_dev}:{info.st_ino}':
        raise RuntimeError('Guest and host image identities differ')
    marker_dir = LOCAL_ROOT / '.vhdx-handoff' / 'operations'
    marker_stat = os.stat(marker_dir, follow_symlinks=False)
    if not stat.S_ISDIR(marker_stat.st_mode):
        raise RuntimeError('Host coordination marker path is not a directory')
    guest_marker = str(GUEST_ROOT / '.vhdx-handoff' / 'operations')
    guest_marker_id = _pct('stat','-c','%d:%i','--',guest_marker)
    if guest_marker_id != f'{marker_stat.st_dev}:{marker_stat.st_ino}':
        raise RuntimeError('Guest and host coordination directory identities differ')


def _load_vendor():
    """Load only root-owned, pinned SMB dependencies from the adjacent vendor dir."""
    module = Path(__file__).absolute()
    install_dir = module.parent
    vendor = install_dir / 'vendor'
    def check(path, directory=False):
        info = os.stat(path, follow_symlinks=False)
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Untrusted VHDX helper or vendored dependency: ' + str(path))
    try:
        check(install_dir, True); check(module); check(vendor, True)
        for directory, dirs, files in os.walk(vendor, followlinks=False):
            for name in dirs: check(Path(directory)/name, True)
            for name in files: check(Path(directory)/name)
        for package, version, dist_dir in (
            ('smbprotocol','1.17.0','smbprotocol-1.17.0.dist-info'),
            ('pyspnego','0.12.4','pyspnego-0.12.4.dist-info')):
            meta = importlib.metadata.Distribution.at(vendor/dist_dir).metadata
            if meta.get('Name','').lower() != package or meta.get('Version') != version:
                raise RuntimeError('Unexpected vendored SMB dependency version: ' + package)
    except OSError as e:
        raise RuntimeError('Secure vendored SMB dependencies are unavailable: ' + str(e)) from e
    if str(vendor) not in sys.path: sys.path.insert(0,str(vendor))
    import smbclient, smbprotocol, spnego
    for mod in (smbclient, smbprotocol, spnego):
        try: Path(mod.__file__).resolve(strict=True).relative_to(vendor.resolve(strict=True))
        except (ValueError,OSError,TypeError) as e:
            raise RuntimeError('SMB dependency was loaded from outside the trusted vendor directory') from e
    return smbclient

def _verify_session_mapping(smbclient, cache):
    """Bind this SMB session to this local share with a fresh root-created nonce.

    The directory is protected from non-root mutation; the one-use file is
    readable over the configured share. If Samba hides it, verification fails.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    root_fd = os.open(LOCAL_ROOT, flags)
    current = root_fd
    fd = None
    root_device = os.fstat(root_fd).st_dev
    name = '.vhdx-handoff-probe-' + secrets.token_hex(16)
    try:
        for part in ('.vhdx-handoff', 'operations'):
            nxt = os.open(part, flags, dir_fd=current)
            info = os.fstat(nxt)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_dev != root_device:
                os.close(nxt)
                raise RuntimeError('Untrusted coordination directory for SMB identity probe')
            if current != root_fd: os.close(current)
            current = nxt
        nonce = secrets.token_bytes(32)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o644, dir_fd=current)
        os.fchmod(fd, 0o644)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(nonce); stream.flush(); os.fsync(stream.fileno())
        unc = SMB_ROOT + '\\' + '.vhdx-handoff\\operations\\' + name
        with smbclient.open_file(unc, mode='rb', buffering=0, share_access='rwd', connection_cache=cache) as remote_probe:
            if remote_probe.read(33) != nonce:
                raise RuntimeError('SMB session and local share identity probe differ')
    finally:
        try:
            if fd is not None:
                try:
                    held = os.fstat(fd)
                    entry = os.stat(name, dir_fd=current, follow_symlinks=False)
                    if (held.st_dev, held.st_ino) != (entry.st_dev, entry.st_ino):
                        raise RuntimeError('SMB identity probe changed during verification')
                    os.unlink(name, dir_fd=current)
                finally:
                    os.close(fd)
        finally:
            if current != root_fd: os.close(current)
            os.close(root_fd)


def _connect(relative, root_stat):
    # A private connection cache avoids using another part of the program's session.
    try:
        smbclient = _load_vendor()
    except ImportError as e:
        raise RuntimeError('smbprotocol 1.17.0 and pyspnego 0.12.4 are required') from e
    cache = {}
    remote = None
    try:
        smbclient.ClientConfig(require_secure_negotiate=False)
        smbclient.register_session(SMB_HOST, username=GUEST_USERNAME, password='',
            auth_protocol='ntlm', require_signing=False, encrypt=False, connection_cache=cache)
        root = smbclient.stat(SMB_ROOT, follow_symlinks=False, connection_cache=cache)
        if root.st_ino != root_stat.st_ino:
            raise RuntimeError('SMB share root and host root identities differ')
        unc = SMB_ROOT + '\\' + '\\'.join(relative.parts)
        remote = smbclient.open_file(unc, mode='rb+', buffering=0, share_access='',
                                     connection_cache=cache)
        _verify_session_mapping(smbclient, cache)
        return remote, cache, smbclient
    except BaseException:
        if remote is not None: remote.close()
        smbclient.reset_connection_cache(fail_on_error=False, connection_cache=cache)
        raise


def _same_handle_info(remote):
    # Query the *held* handle: a new stat/open would conflict with our own guard.
    from smbclient._io import SMBFileTransaction, query_info
    from smbprotocol.file_info import FileInternalInformation, FileStandardInformation
    with SMBFileTransaction(remote) as tx:
        query_info(tx, FileInternalInformation)
        query_info(tx, FileStandardInformation)
    return (tx.results[0]['index_number'].get_value(),
            tx.results[1]['end_of_file'].get_value())


class VerifiedGuard:
    def __init__(self, fd, parent_fd, name, remote, info):
        self._fd, self._parent_fd, self._name, self._remote = fd, parent_fd, name, remote
        self.device, self.inode, self.size = info.st_dev, info.st_ino, info.st_size
        self.verified = False

    def assert_still_exclusive(self):
        """Fail if held SMB handle, local fd, or local directory entry changed."""
        if self._fd is None or self._remote is None:
            raise RuntimeError('SMB guard is closed')
        try:
            smb_inode, _ = _same_handle_info(self._remote)
            local = os.fstat(self._fd)
            entry = os.stat(self._name, dir_fd=self._parent_fd, follow_symlinks=False)
            if (smb_inode != self.inode or
                (local.st_dev,local.st_ino) != (self.device,self.inode) or
                (entry.st_dev,entry.st_ino) != (self.device,self.inode) or
                not stat.S_ISREG(entry.st_mode)):
                raise RuntimeError('Image identity changed while guard was held')
        except BaseException:
            self.verified = False
            raise
        self.verified = True
        return None


@contextmanager
def acquire_verified_guard(image_path):
    """Acquire exclusive SMB open, verify mappings, and yield a VerifiedGuard.

    Only valid for the explicitly configured share and dataset. The caller must
    not release this context until writable mounts and NBD connections are gone.
    """
    fd = parent = root_fd = None
    remote = smbclient = None
    cache = None
    guard = None
    try:
        fd, parent, root_fd, relative, root_stat, info = _checked_local(image_path)
        _mapping_check(relative, info)
        remote, cache, smbclient = _connect(relative, root_stat)
        smb_inode, smb_size = _same_handle_info(remote)
        if smb_inode != info.st_ino or smb_size != info.st_size:
            raise RuntimeError('SMB and host image identity or size differs')
        guard = VerifiedGuard(fd,parent,relative.name,remote,info)
        guard.assert_still_exclusive()
        yield guard
    finally:
        if guard is not None:
            guard.verified = False
            guard._fd = None
            guard._remote = None
        try:
            if remote is not None: remote.close()
        finally:
            try:
                if smbclient is not None:
                    smbclient.reset_connection_cache(fail_on_error=False, connection_cache=cache)
            finally:
                try:
                    if fd is not None: os.close(fd)
                finally:
                    try:
                        if parent is not None and parent != root_fd: os.close(parent)
                    finally:
                        if root_fd is not None: os.close(root_fd)

