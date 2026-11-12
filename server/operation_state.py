"""Durable per-image unresolved-operation markers, guarded by inode flock.

The caller holds a shared or exclusive flock on the *same image inode* throughout
all operations on this store. A marker is keyed by numeric st_dev-st_ino. The
root-owned directories are read-only to ordinary users. Existing, malformed, or
unreadable markers always block access. This module never blindly clears one.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import time
import re

# Populated from a trusted host configuration at helper startup.
HOST_DIR = None
GUEST_DIR = None

class MarkerError(Exception):
    pass

def marker_name(info: os.stat_result) -> str:
    return f"{info.st_dev}-{info.st_ino}.json"

class MarkerStore:
    def __init__(self, directory: Path, expected_owner: int = 0):
        self.path=Path(directory)
        self.fd=-1
        for path in (self.path.parent.parent, self.path.parent, self.path):
            try:
                meta=os.lstat(path)
            except OSError as exc:
                raise MarkerError(f"Marker directory unavailable: {exc}") from exc
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != expected_owner or meta.st_mode & 0o022:
                raise MarkerError(f"Marker directory is not safely owned: {path}")
        try:
            self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0))
            actual=os.fstat(self.fd);named=os.lstat(self.path)
            if (actual.st_dev,actual.st_ino)!=(named.st_dev,named.st_ino):
                raise MarkerError("Marker directory changed during validation")
        except Exception:
            if self.fd>=0: os.close(self.fd)
            self.fd=-1
            raise
    def __enter__(self): return self
    def __exit__(self,*args):
        if self.fd>=0: os.close(self.fd);self.fd=-1
    def exists(self, info: os.stat_result) -> bool:
        try:
            os.stat(marker_name(info),dir_fd=self.fd,follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise MarkerError(f"Cannot check operation marker: {exc}") from exc
    def create(self, info: os.stat_result, image: str):
        name=marker_name(info)
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0),0o644,dir_fd=self.fd)
        except FileExistsError as exc:
            raise MarkerError("Unresolved operation marker exists; do not attach or modify this image") from exc
        except OSError as exc:
            raise MarkerError(f"Cannot create operation marker: {exc}") from exc
        try:
            boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            # /proc/<pid>/stat fields after the final ')' start at field 3;
            # starttime is field 22, index 19 in that suffix.
            process_start=Path("/proc/self/stat").read_text().rsplit(")",1)[1].split()[19]
            namespace=os.readlink("/proc/self/ns/mnt")
        except (OSError, IndexError) as exc:
            os.close(fd)
            raise MarkerError(f"Cannot establish process identity; marker remains blocking: {exc}") from exc
        marker=Marker(self,name,fd,{"image":image,"device":info.st_dev,"inode":info.st_ino,"pid":os.getpid(),"process_start_ticks":process_start,"boot_id":boot_id,"namespace":namespace,"started_unix":time.time(),"phase":"reserved"})
        # A marker existing but incomplete is still a blocking marker after crash.
        try:
            os.fchmod(fd,0o644);marker.update();os.fsync(self.fd)
        except Exception:
            os.close(fd);marker.fd=-1
            raise
        return marker

class Marker:
    def __init__(self,store,name,fd,data): self.store,self.name,self.fd,self.data=store,name,fd,data
    def update(self, **changes):
        self.data.update(changes)
        raw=(json.dumps(self.data,sort_keys=True)+"\n").encode("utf-8")
        os.lseek(self.fd,0,os.SEEK_SET);os.ftruncate(self.fd,0)
        with os.fdopen(os.dup(self.fd),"wb") as output:
            output.write(raw);output.flush();os.fsync(output.fileno())
    def clear(self):
        # Ensure no different marker was substituted before removing it.
        opened=os.fstat(self.fd);named=os.stat(self.name,dir_fd=self.store.fd,follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
            raise MarkerError("Operation marker changed; refusing to clear it")
        os.unlink(self.name,dir_fd=self.store.fd);os.fsync(self.store.fd)
        os.close(self.fd);self.fd=-1
    def close(self):
        if self.fd>=0: os.close(self.fd);self.fd=-1


