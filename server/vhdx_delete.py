#!/usr/bin/python3 -I
"""Guarded deletion inside an offline NTFS VHDX.

Usage: vhdx_delete.py --expected-config-digest DIGEST -- IMAGE PARTITION RELATIVE_PATH file|dir

It refuses to act without the separate
smb_guard.acquire_verified_guard implementation. That guard must hold an
exclusive SMB open and verify server/device/inode/size identity throughout the
entire operation. Run only as root on the storage host with a private mount
namespace, qemu-nbd, ntfs-3g and the sibling delete_inside_mount.py installed.
Never use on an attached, hibernated, dirty, or concurrently modified image.

If cleanup fails, this process intentionally keeps the guard and image open and
retries: do not kill it or reconnect the image. This limits normal failures; no
user-space program can retain an SMB lease after machine failure or SIGKILL.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import fcntl
import glob
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

def _configure_trusted_imports() -> None:
    """Allow sibling imports under Python -I only from a root-owned code dir."""
    script = Path(os.path.abspath(__file__))
    parent = script.parent
    if os.path.realpath(parent) != str(parent):
        raise RuntimeError("Helper directory crosses a symbolic link")
    for directory in (parent, *parent.parents):
        meta = os.lstat(directory)
        # A root-owned sticky directory such as /tmp is acceptable for an
        # isolated scratch test; sticky protection prevents renaming the
        # root-owned child. Production should live under /opt.
        writable = bool(meta.st_mode & 0o022)
        sticky = bool(meta.st_mode & stat.S_ISVTX)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or (writable and not sticky):
            raise RuntimeError(f"Unsafe helper directory: {directory}")
    for path in (script, parent / "delete_inside_mount.py", parent / "operation_state.py", parent / "smb_guard.py", parent / "host_config.py"):
        meta = os.lstat(path)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise RuntimeError(f"Unsafe helper ownership or permissions: {path}")
    sys.path.insert(0, str(parent))


if __name__ == "__main__":
    try:
        _configure_trusted_imports()
    except (OSError, RuntimeError) as exc:
        print(f"Untrusted VHDX helper installation: {exc}", file=sys.stderr)
        sys.exit(1)

from delete_inside_mount import DeleteError, _components
from operation_state import MarkerError, MarkerStore, HOST_DIR


def configure_guard(expected_digest: str | None = None):
    """Load the root-controlled mapping; missing/untrusted config fails closed."""
    global HOST_DIR
    import host_config
    import smb_guard
    try:
        config, digest = host_config.load_with_digest()
        if expected_digest is not None:
            if not re.fullmatch(r'[0-9a-f]{64}', expected_digest) or digest != expected_digest:
                raise ValueError('Guard configuration changed; re-check the mapping')
        smb_guard.configure(config)
        HOST_DIR = Path(config['local_root']) / '.vhdx-handoff' / 'operations'
        return config, digest
    except (OSError, ValueError, KeyError) as exc:
        raise SafetyError('Host deletion guard is not safely configured: ' + str(exc)) from exc


def verify_status_mapping(image: str) -> None:
    """Only report clear after host/guest image and marker identities agree."""
    import smb_guard
    fd = parent = root = None
    try:
        fd, parent, root, relative, _root_stat, info = smb_guard._checked_local(image)
        smb_guard._mapping_check(relative, info)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SafetyError('Cannot verify configured host/guest mapping: ' + str(exc)) from exc
    finally:
        if fd is not None: os.close(fd)
        if parent is not None and parent != root: os.close(parent)
        if root is not None: os.close(root)


class SafetyError(Exception):
    pass


class GuardLost(SafetyError):
    """The share-deny lease or its verified identity was lost."""


class StopRequested(Exception):
    """A termination request that must pass through the cleanup finally block."""


def _report(message: str) -> None:
    # The SSH client may disconnect while cleanup is in progress. Logging must
    # never break cleanup and release the share-deny lease prematurely.
    try:
        print(message, file=sys.stderr, flush=True)
    except OSError:
        pass


@contextlib.contextmanager
def _controlled_signals():
    old = {}
    def stop(signum, frame):
        raise StopRequested(f"Signal {signum} received; cleaning up safely")
    try:
        for sig, handler in ((signal.SIGHUP, signal.SIG_IGN), (signal.SIGINT, stop), (signal.SIGTERM, stop)):
            old[sig] = signal.getsignal(sig)
            signal.signal(sig, handler)
        yield
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def acquire_verified_guard(image: str):
    """Fail closed unless the separately installed SMB guard is available.

    The returned context must yield an object with verified=True, integer device,
    inode, size, and assert_still_exclusive(); the context must retain the SMB
    share-deny handle until exit. There is deliberately no command-line bypass.
    """
    try:
        from smb_guard import acquire_verified_guard as acquire
    except Exception as exc:
        raise SafetyError(f"Exclusive SMB guard is unavailable: {exc}") from exc
    return acquire(image)


def _verify_guard(guard, image_stat: os.stat_result, *, check_size: bool) -> None:
    if getattr(guard, "verified", None) is not True:
        raise SafetyError("Exclusive SMB guard was not verified")
    if (getattr(guard, "device", None), getattr(guard, "inode", None)) != (image_stat.st_dev, image_stat.st_ino):
        raise SafetyError("SMB guard and local image do not refer to the same file")
    if check_size and getattr(guard, "size", None) != image_stat.st_size:
        raise SafetyError("Image size changed while acquiring the SMB guard")
    if not callable(getattr(guard, "assert_still_exclusive", None)):
        raise SafetyError("SMB guard cannot verify its live exclusive handle")
    _assert_guard(guard)


def _run(args: list[str], *, pass_fds: tuple[int, ...] = (), timeout: float = 30.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, pass_fds=pass_fds)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafetyError(f"Command failed ({args[0]}): {exc}") from exc


def _check_local_writers(guard, image_fd: int) -> None:
    """Reject visible local holders other than us and the guarded smbd.

    This is advisory and cannot prevent a non-cooperating local process from
    opening the image immediately after the check; such writers are unsupported.
    """
    _assert_guard(guard)
    path=f"/proc/self/fd/{image_fd}"
    try:
        result=subprocess.run(["fuser",path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,timeout=10.0,pass_fds=(image_fd,))
    except (OSError,subprocess.SubprocessError) as exc:
        raise SafetyError(f"Cannot inspect local image holders: {exc}") from exc
    if result.returncode not in (0,1):
        raise SafetyError(f"Local holder inspection failed (exit {result.returncode})")
    try:
        pids={int(token) for token in result.stdout.split()}
    except ValueError as exc:
        raise SafetyError("Local holder inspection returned unexpected output") from exc
    if os.getpid() not in pids:
        raise SafetyError("Local holder inspection could not see this process; refusing")
    samba_holders=0
    for pid in pids:
        if pid==os.getpid(): continue
        try:
            executable=os.readlink(f"/proc/{pid}/exe")
        except FileNotFoundError:
            continue  # a transient probe process exited after fuser observed it
        except OSError as exc:
            raise SafetyError(f"Cannot identify local holder PID {pid}: {exc}") from exc
        if os.path.basename(executable)=="smbd":
            samba_holders+=1
        else:
            raise SafetyError(f"Another local process has the image open (PID {pid})")
    if samba_holders != 1:
        raise SafetyError(f"Could not uniquely identify the guarded Samba holder ({samba_holders} found)")
    _assert_guard(guard)

def _private_namespace() -> None:
    # unshare changes this process and its child processes only, not the host's
    # mount namespace. The guard and locked descriptors stay open across it.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x00020000) != 0:  # CLONE_NEWNS
        error = ctypes.get_errno()
        raise SafetyError(f"Cannot create private mount namespace: {os.strerror(error)}")
    _run(["mount", "--make-rprivate", "/"])


@contextlib.contextmanager
def _nbd_allocation_lock():
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open("/run/lock/vhdx-handoff-nbd.lock", flags, 0o600)
    except OSError as exc:
        raise SafetyError(f"Cannot open the NBD allocation lock: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise SafetyError("NBD allocation lock is not a root-owned regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _nbd_pid(device: str) -> int | None:
    name = os.path.basename(device)
    try:
        value = Path("/sys/block", name, "pid").read_text().strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SafetyError(f"Cannot check ownership of {device}: {exc}") from exc
    if not value:
        return None
    try:
        pid = int(value)
    except ValueError as exc:
        raise SafetyError(f"Unexpected NBD process identifier for {device}") from exc
    if pid <= 0:
        raise SafetyError(f"Unexpected NBD process identifier for {device}")
    return pid


def _process_start_ticks(pid: int) -> int:
    """Bind an NBD PID to its Linux process-start identity, not PID alone."""
    try:
        suffix=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
        return int(suffix[19])  # /proc stat field 22; suffix starts at field 3
    except (OSError,IndexError,ValueError) as exc:
        raise SafetyError(f"Cannot verify NBD owner identity for PID {pid}: {exc}") from exc

def _ensure_nbd_module(partition: int) -> None:
    module = Path("/sys/module/nbd")
    if not module.is_dir():
        # This is a shared host module. Load only on demand and do not unload it.
        _run(["modprobe", "nbd", "max_part=16"])
    try:
        max_part = int((module / "parameters" / "max_part").read_text().strip())
    except (OSError, ValueError) as exc:
        raise SafetyError(f"Cannot verify NBD partition capacity: {exc}") from exc
    if max_part < partition:
        raise SafetyError(f"NBD supports only {max_part} partitions, but partition {partition} is required")

def _available_nbd() -> str:
    for device in sorted(glob.glob("/dev/nbd*")):
        if re.fullmatch(r"/dev/nbd\d+", device) and _nbd_pid(device) is None:
            return device
    raise SafetyError("No unused NBD device is available; the driver/devices must already exist")


def _wait_for_partition(guard, device: str, partition: int, timeout: float = 10.0) -> str:
    path = f"{device}p{partition}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _assert_guard(guard)
        if os.path.exists(path):
            _assert_guard(guard)
            return path
        time.sleep(0.1)
    raise SafetyError(f"Partition device {path} did not appear; check NBD partition support")


def _is_mountpoint(path: str) -> bool:
    """Inspect this private mount namespace; unknown/malformed state is unsafe."""
    if not os.path.isabs(path):
        raise SafetyError("Mountpoint path must be absolute")
    target = os.path.normpath(path)
    try:
        # Linux mountinfo is authoritative for this process's mount namespace.
        # Decode its documented octal escapes (space, tab, newline, backslash).
        lines = Path("/proc/self/mountinfo").read_text(errors="surrogateescape").splitlines()
    except OSError as exc:
        raise SafetyError(f"Cannot inspect private mount namespace: {exc}") from exc
    if not lines:
        raise SafetyError("Private mount namespace has no mountinfo entries")
    for line in lines:
        before, separator, after = line.partition(" - ")
        fields = before.split()
        if not separator or len(fields) < 6 or len(after.split()) < 3:
            raise SafetyError("Private mount namespace returned malformed mountinfo")
        mount_path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        if os.path.normpath(mount_path) == target:
            return True
    return False

def _terminate_child(process) -> None:
    # A repeated TERM/INT cannot interrupt child shutdown and let a live
    # deleter race cleanup. Pending signals are delivered after child exit.
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _assert_guard(guard) -> None:
    try:
        guard.assert_still_exclusive()
    except Exception as exc:
        raise GuardLost(f"Exclusive SMB guard was lost; operation stopped and changes may be partial: {exc}") from exc


def _run_guarded_command(guard, args: list[str], *, pass_fds: tuple[int, ...] = (), timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Continuously check the SMB guard while a writable-image stage runs."""
    process = None
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            _assert_guard(guard)
            process = subprocess.Popen(args, stdout=output, stderr=errors, start_new_session=True, pass_fds=pass_fds,
                                       env={**os.environ, "LC_ALL": "C"})
            deadline=time.monotonic()+timeout
            while True:
                _assert_guard(guard)
                remaining=deadline-time.monotonic()
                if remaining <= 0:
                    raise SafetyError(f"Command timed out: {args[0]}")
                try:
                    status=process.wait(timeout=min(0.5,remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            _assert_guard(guard)
            output.seek(0); errors.seek(0)
            raw=output.read(16*1024*1024+1)
            if len(raw)>16*1024*1024: raise SafetyError(f"Output from {args[0]} exceeds safe inspection limit")
            stdout=raw.decode("utf-8","replace")
            stderr=errors.read(8192).decode("utf-8","replace")
            if status != 0:
                raise SafetyError(f"Command failed ({args[0]}, exit {status}): {stderr.strip()}")
            return subprocess.CompletedProcess(args,status,stdout,stderr)
        except BaseException as exc:
            if process is not None:
                _terminate_child(process)
            if isinstance(exc, OSError):
                raise SafetyError(f"Cannot start or monitor {args[0]}: {exc}") from exc
            raise

def _reject_backing_chain(guard, image_fd: int) -> None:
    """Fail closed if the image depends on any parent/backing disk."""
    result = _run_guarded_command(guard, ["qemu-img", "info", "-f", "vhdx", "--output=json", "--backing-chain", f"/proc/self/fd/{image_fd}"], pass_fds=(image_fd,))
    try:
        chain = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise SafetyError(f"Cannot parse VHDX backing-chain information: {exc}") from exc
    if not isinstance(chain, list) or len(chain) != 1 or not isinstance(chain[0], dict):
        raise SafetyError("Differencing or uncertain VHDX backing chains are unsupported")
    entry = chain[0]
    if entry.get("format") != "vhdx" or entry.get("backing-filename") or entry.get("full-backing-filename"):
        raise SafetyError("Differencing VHDX images with backing files are unsupported")

def _run_guarded_delete(guard, helper: str, mount_dir: str, relative_path: str, expected: str) -> None:
    """Recheck the SMB lease before each unlink/rmdir and throughout deletion."""
    request_read, request_write = os.pipe()
    reply_read, reply_write = os.pipe()
    process = None
    try:
        args = [sys.executable, "-I", helper, "--guard-request-fd", str(request_write),
                "--guard-response-fd", str(reply_read), "--", mount_dir, relative_path, expected]
        with tempfile.TemporaryFile() as errors:
            _assert_guard(guard)
            try:
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors,
                                           start_new_session=True, pass_fds=(request_write, reply_read))
            except OSError as exc:
                raise SafetyError(f"Could not start deletion helper: {exc}") from exc
            os.close(request_write); request_write = -1
            os.close(reply_read); reply_read = -1
            with selectors.DefaultSelector() as selector:
                selector.register(request_read, selectors.EVENT_READ)
                while True:
                    # Even during slow traversal, check the live share-deny handle.
                    _assert_guard(guard)
                    events = selector.select(timeout=0.5)
                    if events:
                        message = os.read(request_read, 1)
                        if message:
                            if message != b"G":
                                raise SafetyError("Invalid request from deletion helper")
                            _assert_guard(guard)
                            os.write(reply_write, b"Y")
                        else:
                            # EOF means the child closed its request end; wait for
                            # its exit rather than repeatedly receiving empty data.
                            selector.unregister(request_read)
                    status = process.poll()
                    if status is not None:
                        break
                _assert_guard(guard)
                if status != 0:
                    errors.seek(0)
                    message = errors.read(8192).decode("utf-8", "replace").strip()
                    raise SafetyError(f"Deletion helper failed (exit {status}): {message}. Changes may be partial.")
    except BaseException:
        if process is not None:
            _terminate_child(process)
        raise
    finally:
        for fd in (request_read, request_write, reply_read, reply_write):
            if fd >= 0:
                os.close(fd)


def _observe_guard_for_cleanup(guard, state: dict) -> None:
    # Loss does not block cleanup: disconnecting the writable stack is urgent.
    # It does force an unresolved marker even if cleanup ultimately succeeds.
    if state.get("guard_lost") is None:
        try:
            _assert_guard(guard)
        except GuardLost as exc:
            state["guard_lost"] = exc
            _report(f"SMB guard lost during cleanup; stopping writable access: {exc}")


def _run_cleanup_command(guard, state: dict, args: list[str], *, timeout: float = 20.0) -> None:
    process = None
    with tempfile.TemporaryFile() as errors:
        try:
            _observe_guard_for_cleanup(guard,state)
            process=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=errors,start_new_session=True)
            deadline=time.monotonic()+timeout
            while True:
                _observe_guard_for_cleanup(guard,state)
                remaining=deadline-time.monotonic()
                if remaining<=0: raise SafetyError(f"Cleanup command timed out: {args[0]}")
                try:
                    status=process.wait(timeout=min(0.5,remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            _observe_guard_for_cleanup(guard,state)
            if status!=0:
                errors.seek(0)
                raise SafetyError(f"Cleanup command failed ({args[0]}, exit {status}): {errors.read(8192).decode('utf-8','replace').strip()}")
        except BaseException as exc:
            if process is not None: _terminate_child(process)
            if isinstance(exc,OSError): raise SafetyError(f"Cannot start cleanup command: {exc}") from exc
            raise


def _cleanup_once(guard, state: dict, device: str, owner_pid: int | None, owner_start: int | None, mount_dir: str | None,
                  mount_attempted: bool, attach_attempted: bool) -> None:
    _observe_guard_for_cleanup(guard,state)
    if mount_attempted and mount_dir is not None and _is_mountpoint(mount_dir):
        _run_cleanup_command(guard,state,["umount", "--", mount_dir],timeout=20.0)
        if _is_mountpoint(mount_dir):
            raise SafetyError("The private NTFS mount is still active")
    _observe_guard_for_cleanup(guard,state)
    if attach_attempted:
        current = _nbd_pid(device)
        if current is not None:
            if owner_pid is None or owner_start is None or current != owner_pid or _process_start_ticks(current) != owner_start:
                raise SafetyError(f"NBD ownership for {device} is uncertain; refusing to disconnect it")
            _run_cleanup_command(guard,state,["qemu-nbd", "--disconnect", device],timeout=20.0)
            if _nbd_pid(device) is not None:
                raise SafetyError(f"NBD device {device} remains connected")
    _observe_guard_for_cleanup(guard,state)


def _cleanup_holding_guard(guard, device: str, owner_pid: int | None, owner_start: int | None, mount_dir: str | None,
                           mount_attempted: bool, attach_attempted: bool) -> None:
    reported = False
    state = {"guard_lost": None}
    while True:
        try:
            _cleanup_once(guard,state,device,owner_pid,owner_start,mount_dir,mount_attempted,attach_attempted)
        except (Exception, KeyboardInterrupt) as exc:
            if not reported:
                _report(f"SAFE HOLD: cleanup failed ({exc}). The image guard remains held; "
                        "do not reconnect the image or stop this process. Retrying cleanup.")
                reported = True
            try:
                time.sleep(5.0)
            except (KeyboardInterrupt, StopRequested):
                _report("SAFE HOLD remains active; cleanup must complete first.")
        else:
            if state["guard_lost"] is not None:
                raise state["guard_lost"]
            return

def _open_and_lock(image: str, *, exclusive: bool) -> tuple[int, os.stat_result]:
    flags = (os.O_RDWR if exclusive else os.O_RDONLY) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(image, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SafetyError("The image is not a regular file")
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SafetyError("Image is busy with another app-managed operation") from exc
        return fd, info
    except Exception:
        if 'fd' in locals(): os.close(fd)
        raise


def status_vhdx(image: str, guard=None) -> str:
    """Read-only status; any lock, marker or state uncertainty fails closed."""
    if not os.path.isabs(image) or not image.lower().endswith((".vhdx", ".vhd")):
        raise SafetyError("An absolute .vhd or .vhdx image path is required")
    fd, info = _open_and_lock(image, exclusive=False)
    try:
        if guard is not None:
            _verify_guard(guard, info, check_size=True)
        with MarkerStore(HOST_DIR) as store:
            if store.exists(info):
                raise SafetyError("UNRESOLVED: a prior deletion needs manual inspection; do not attach or modify this image")
        if guard is not None:
            _assert_guard(guard)
        return "CLEAR: no app-managed deletion is active or unresolved (external users are not checked)."
    finally:
        os.close(fd)


def _perform_guarded_operation(guard, image_fd: int, partition: int, relative_path: str, expected: str, marker) -> None:
    _private_namespace()
    with _nbd_allocation_lock():
        _ensure_nbd_module(partition)
        device = _available_nbd()
        mount_dir = None
        owner_pid = None
        owner_start = None
        attach_attempted = False
        mount_attempted = False
        try:
            _verify_guard(guard, os.fstat(image_fd), check_size=True)
            _check_local_writers(guard, image_fd)
            _reject_backing_chain(guard, image_fd)
            # Durably record the device before the first write-capable attach.
            marker.update(phase="nbd-attaching", nbd=device)
            attach_attempted = True
            _run_guarded_command(guard, ["qemu-nbd", "--connect", device, "--format=vhdx", "--cache=none",
                          f"/proc/self/fd/{image_fd}"], pass_fds=(image_fd,))
            owner_pid = _nbd_pid(device)
            if owner_pid is None:
                raise SafetyError("NBD ownership could not be verified after attachment")
            owner_start = _process_start_ticks(owner_pid)
            marker.update(phase="nbd-attached", nbd_pid=owner_pid, nbd_start_ticks=owner_start)
            part = _wait_for_partition(guard, device, partition)
            detected = _run_guarded_command(guard, ["blkid", "-p", "-o", "value", "-s", "TYPE", part]).stdout.strip()
            if detected != "ntfs":
                raise SafetyError(f"Selected partition is not NTFS (reported {detected!r})")
            _verify_guard(guard, os.fstat(image_fd), check_size=False)
            mount_dir = tempfile.mkdtemp(prefix="vhdx-handoff-private-", dir="/run")
            marker.update(phase="mounting", mount_dir=mount_dir)
            mount_attempted = True
            # ntfs-3g.probe and norecover alone do not reject the NTFS dirty
            # flag on this host. ntfsinfo without force rejects the verified
            # check-scheduled fixture; any error or unknown status is fatal.
            _run_guarded_command(guard, ["ntfsinfo", "-m", part])
            _run_guarded_command(guard, ["ntfs-3g.probe", "--readwrite", part])
            listing = _run_guarded_command(guard, ["ntfsls", "-a", "-p", "/", part]).stdout
            if any(line.strip().casefold() == "hiberfil.sys" for line in listing.splitlines()):
                raise SafetyError("A hiberfil.sys is present; refusing a potentially hibernated Windows volume")
            _run_guarded_command(guard, ["ntfs-3g", "-o", "norecover,nodev,nosuid,noexec", part, mount_dir])
            if not _is_mountpoint(mount_dir):
                raise SafetyError("NTFS mount did not appear in the private namespace")
            marker.update(phase="mounted")
            _verify_guard(guard, os.fstat(image_fd), check_size=False)
            helper = str(Path(__file__).resolve().with_name("delete_inside_mount.py"))
            marker.update(phase="deleting")
            _run_guarded_delete(guard, helper, mount_dir, relative_path, expected)
            marker.update(phase="syncing")
            _run_guarded_command(guard, ["sync", "-f", mount_dir], timeout=60.0)
        finally:
            # Do not leave the guard context while cleanup is unresolved.
            _cleanup_holding_guard(guard, device, owner_pid, owner_start, mount_dir,
                                   mount_attempted, attach_attempted)
            if mount_dir is not None:
                os.rmdir(mount_dir)
            marker.update(phase="resources-cleaned")


def delete_vhdx(image: str, partition: int, relative_path: str, expected: str) -> None:
    _components(relative_path)  # fail before touching the image
    if expected not in ("file", "dir"):
        raise SafetyError("Expected type must be file or dir")
    if not os.path.isabs(image) or not image.lower().endswith(".vhdx"):
        raise SafetyError("An absolute .vhdx image path is required")
    if not 1 <= partition <= 128:
        raise SafetyError("Partition number must be between 1 and 128")
    if os.geteuid() != 0:
        raise SafetyError("This operation requires root on the storage host")

    # The image inode flock remains held until after the SMB guard has been
    # positively released and the durable marker removed. A failed release leaves
    # the marker in place; clients must refuse that image until manual recovery.
    image_fd = -1
    store = None
    marker = None
    error = None
    guard_released = False
    guard_context = acquire_verified_guard(image)
    guard = guard_context.__enter__()
    try:
        try:
            image_fd, info = _open_and_lock(image, exclusive=True)
            _verify_guard(guard, info, check_size=True)
            store = MarkerStore(HOST_DIR)
            marker = store.create(info, image)
            _perform_guarded_operation(guard, image_fd, partition, relative_path, expected, marker)
        except BaseException as exc:
            error = exc
        # Verify the lease one final time after unmount and NBD disconnect.
        # Loss at any point leaves a durable unresolved marker even if cleanup
        # otherwise succeeds, because an external writer may have raced us.
        if marker is not None and not isinstance(error, GuardLost):
            try:
                _assert_guard(guard)
            except GuardLost as exc:
                error = exc
        if marker is not None and isinstance(error, GuardLost):
            try:
                marker.update(phase="guard-lost", error=str(error))
            except Exception:
                pass  # The existing marker remains a blocker even if corrupt.
        try:
            # Tell the guard the original operation result; it must never
            # suppress a deletion error or hide failure to close the SMB handle.
            guard_context.__exit__(type(error) if error else None, error,
                                   error.__traceback__ if error else None)
            guard_released = True
        except BaseException as exc:
            error = SafetyError(f"SMB guard release failed; unresolved marker retained: {exc}")
        if marker is not None and guard_released and not isinstance(error, GuardLost):
            marker.clear()
        if error is not None:
            raise error
    finally:
        if marker is not None: marker.close()
        if store is not None: store.__exit__(None, None, None)
        if image_fd >= 0: os.close(image_fd)


def main(argv: list[str] | None = None) -> int:
    # Python isolated mode does not sanitize PATH. Never let a caller choose
    # qemu/NTFS/pct binaries when running this helper with root privileges.
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list == ['--describe']:
        try:
            config, digest = configure_guard()
            print(json.dumps({'version': 1, 'smb_host': config['smb_host'], 'smb_share': config['smb_share'],
                              'local_root': config['local_root'], 'guest_root': config['guest_root'],
                              'config_sha256': digest}, sort_keys=True))
            return 0
        except SafetyError as exc:
            _report(str(exc)); return 1
    if args_list and args_list[0] == "--status":
        status_parser = argparse.ArgumentParser(description="Check for active or unresolved app-managed deletion")
        status_parser.add_argument('--expected-config-digest', required=True)
        status_parser.add_argument("image")
        args = status_parser.parse_args(args_list[1:])  # supports --status -- IMAGE
        try:
            configure_guard(args.expected_config_digest)
            # The share-deny handle binds the configured SMB server, guest and
            # host image identities during the check. A string/path mapping
            # alone is not enough to safely allow an app-initiated mount.
            with acquire_verified_guard(args.image) as guard:
                print(status_vhdx(args.image, guard))
            return 0
        except (SafetyError, MarkerError, OSError, ValueError, RuntimeError) as exc:
            _report(f"BUSY OR UNCERTAIN: {exc}")
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-config-digest', required=True)
    parser.add_argument("image")
    parser.add_argument("partition", type=int)
    parser.add_argument("relative_path")
    parser.add_argument("expected", choices=("file", "dir"))
    args = parser.parse_args(args_list)
    try:
        configure_guard(args.expected_config_digest)
        with _controlled_signals():
            delete_vhdx(args.image, args.partition, args.relative_path, args.expected)
    except (SafetyError, MarkerError, DeleteError, OSError, StopRequested, RuntimeError) as exc:
        _report(str(exc))
        return 1
    print("Deletion complete; private mount and NBD device are disconnected.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


















