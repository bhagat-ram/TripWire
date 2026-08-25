"""
fanotify_watcher.py — Stage 2b (optional, Linux-only)
System-wide file-CHANGE audit, independent of the decoy tripwire in
watcher.py. Where watcher.py only sees activity on a pre-planted set of
decoy paths (inotify requires watching known directories ahead of time),
this uses Linux's fanotify API with FAN_MARK_FILESYSTEM to see every file
actually modified by any process on a whole mount — including folders
nobody configured, decoy or not.

Deliberately watches FAN_CLOSE_WRITE, not FAN_OPEN: FAN_OPEN fires on every
read-only open too (your editor loading a file, the shell resolving a
binary, the browser reading its cache, a package manager statting things),
which is mostly noise and not a "change" at all. FAN_CLOSE_WRITE only fires
once a file that was opened for writing is closed, i.e. its content was
actually (or at least potentially) modified — that's the real signal for
an audit trail meant to answer "what changed", not "what was touched".

This is intentionally a SEPARATE stream from the decoy pipeline
(_on_fs_event / classifier.py in server.py), not a replacement for it:
classifier.py's severity scoring is calibrated on "how many times was a
*decoy* touched in N seconds" — feeding it every write on the disk would
make that math meaningless and bury real signal in normal noise.
Full-system events are instead exposed as their own raw audit trail (REST
/fs-audit, WebSocket "fs_open") for manual review, correlation, or a future
dedicated scorer — they never touch Classifier/PanicController.

REQUIREMENTS (hard Linux/root constraints, not configurable away):
  - Linux only. No macOS/Windows equivalent exists in this codebase.
  - Needs CAP_SYS_ADMIN — in practice, must run as root (sudo). Every
    other part of this app runs fine unprivileged; this module is the
    one piece that changes that.
  - FAN_MARK_FILESYSTEM needs kernel >= 4.20. is_available() checks this
    empirically (tries the real syscalls) rather than parsing uname.

Reliability checkpoints this file must pass:
  - Not-root / not-Linux / too-old-kernel fails fast with a clear reason
    from is_available(), never a bare OSError bubbling out of start().
  - The reader thread never dies from a single bad/unreadable event —
    one malformed record is skipped, not fatal.
  - Every yielded event resolves *something* usable for `process` even if
    /proc/<pid>/exe is unreadable (permission denied on another user's
    process) — falls back to /proc/<pid>/comm, then "pid <n>" if even
    that's gone (process exited between the event and our lookup).
  - fd from the kernel is always closed, even on an exception mid-parse,
    or the process leaks file descriptors under load.
  - Marking failure on one path (e.g. filesystem doesn't support fanotify,
    like some network mounts) is logged and skipped, not fatal to the
    whole watcher — other configured mounts keep working.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import select
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


# ─── raw fanotify constants (linux/fanotify.h) ─────────────────────────────
FAN_CLASS_NOTIF      = 0x00000000
FAN_CLOEXEC          = 0x00000001
FAN_NONBLOCK         = 0x00000002

FAN_MARK_ADD         = 0x00000001
FAN_MARK_REMOVE      = 0x00000002
FAN_MARK_FILESYSTEM  = 0x00000100

FAN_OPEN             = 0x00000020
FAN_ACCESS           = 0x00000001
FAN_CLOSE_WRITE      = 0x00000008
FAN_Q_OVERFLOW       = 0x00004000

AT_FDCWD             = -100

# struct fanotify_event_metadata is 24 bytes on every supported arch
# (u32 event_len; u8 vers; u8 reserved; u16 metadata_len; u64 mask;
#  s32 fd; s32 pid;)
_META_FMT  = "=IBBHqii"
_META_SIZE = struct.calcsize(_META_FMT)
assert _META_SIZE == 24, f"unexpected fanotify_event_metadata size {_META_SIZE}"

_FAN_NOFD = -1


@dataclass
class FileOpenEvent:
    pid: int
    process_name: str
    exe_path: Optional[str]
    file_path: Optional[str]   # None if the kernel fd couldn't be resolved
    ts: float


EventCallback = Callable[[FileOpenEvent], None]


def _load_libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c")
    if not name:
        raise OSError("could not locate libc — fanotify bindings unavailable")
    libc = ctypes.CDLL(name, use_errno=True)
    libc.fanotify_init.restype  = ctypes.c_int
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    libc.fanotify_mark.restype  = ctypes.c_int
    libc.fanotify_mark.argtypes = [
        ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p,
    ]
    return libc


def is_available() -> tuple[bool, str]:
    """Best-effort empirical check: can we actually init + mark a filesystem
    watch right now? Returns (ok, reason). Cheap — opens and immediately
    closes a throwaway fanotify fd rather than trusting platform.system()
    or a kernel-version string, since what matters is whether the syscalls
    themselves succeed under the current privileges/kernel.
    """
    if os.name != "posix" or not os.path.exists("/proc"):
        return False, "fanotify is Linux-only"
    try:
        libc = _load_libc()
    except OSError as e:
        return False, str(e)

    fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                             os.O_RDONLY)
    if fd < 0:
        errno = ctypes.get_errno()
        if errno == 1:  # EPERM
            return False, "permission denied — fanotify requires root (CAP_SYS_ADMIN)"
        return False, f"fanotify_init failed (errno={errno})"

    try:
        # Probe with the same mask actually used by FanotifyWatcher below
        # (FAN_CLOSE_WRITE) so availability reflects the real code path,
        # not a different event type that might behave differently on some
        # kernel/filesystem combos.
        rc = libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                                 FAN_CLOSE_WRITE, AT_FDCWD, b"/")
        if rc < 0:
            errno = ctypes.get_errno()
            if errno == 95:  # ENOSYS / EOPNOTSUPP-ish depending on kernel
                return False, "FAN_MARK_FILESYSTEM unsupported — needs kernel >= 4.20"
            return False, f"fanotify_mark failed (errno={errno})"
    finally:
        os.close(fd)
    return True, "ok"


def _proc_name(pid: int) -> tuple[str, Optional[str]]:
    """(comm, exe_path). Never raises — permission errors or a process that
    already exited both fall back gracefully."""
    comm = f"pid {pid}"
    try:
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip() or comm
    except OSError:
        pass
    exe_path: Optional[str] = None
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    return comm, exe_path


class FanotifyWatcher:
    """
    Watches one or more whole filesystems (mount points) for FAN_CLOSE_WRITE
    (a file that was opened for writing has been closed — i.e. it actually
    changed, or at least was writable-opened) via fanotify. Unlike
    watcher.py's Watcher, there is no known-paths filter — every write
    under the marked mount is reported; the caller decides what to do with
    the firehose. Read-only opens (FAN_OPEN) are deliberately NOT watched
    here — see the module docstring for why that would be mostly noise for
    a change-audit trail.

    Usage:
        ok, reason = is_available()
        if ok:
            w = FanotifyWatcher(mounts=["/home"], callback=my_fn)
            w.start()
            ...
            w.stop()
    """

    def __init__(
        self,
        mounts: list[str],
        callback: Optional[EventCallback] = None,
        event_mask: int = FAN_CLOSE_WRITE,
        ignore_prefixes: Optional[list[str]] = None,
    ):
        if not mounts:
            raise ValueError("FanotifyWatcher needs at least one mount/path to mark")
        self.mounts = list(mounts)
        self.callback = callback or (lambda *_a, **_kw: None)
        self.event_mask = event_mask
        # Paths under these prefixes are dropped before the callback fires —
        # primarily so this watcher doesn't report its own log/DB writes
        # (which would otherwise self-feed: writing an audit entry about an
        # open triggers another open event, forever).
        self.ignore_prefixes = [os.path.realpath(p) for p in (ignore_prefixes or [])]
        self._self_pid = os.getpid()

        self._libc: Optional[ctypes.CDLL] = None
        self._fan_fd: Optional[int] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._marked_mounts: list[str] = []
        self._error: Optional[str] = None

    # ── public API ──────────────────────────────────────────────────────

    def start(self):
        ok, reason = is_available()
        if not ok:
            self._error = reason
            raise PermissionError(f"cannot start FanotifyWatcher: {reason}")

        self._libc = _load_libc()
        fd = self._libc.fanotify_init(
            FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
            os.O_RDONLY | getattr(os, "O_LARGEFILE", 0),
        )
        if fd < 0:
            errno = ctypes.get_errno()
            raise OSError(f"fanotify_init failed (errno={errno})")
        self._fan_fd = fd

        self._marked_mounts = []
        for m in self.mounts:
            rc = self._libc.fanotify_mark(
                self._fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                self.event_mask, AT_FDCWD, os.fsencode(m),
            )
            if rc < 0:
                errno = ctypes.get_errno()
                # One bad mount (e.g. a network share that rejects fanotify
                # marks) shouldn't take down monitoring of the others.
                self._error = f"failed to mark {m!r} (errno={errno})"
                continue
            self._marked_mounts.append(m)

        if not self._marked_mounts:
            os.close(self._fan_fd)
            self._fan_fd = None
            raise OSError(self._error or "no mount could be marked")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._read_loop, daemon=True, name="tripwire-fanotify"
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        if self._fan_fd is not None:
            os.close(self._fan_fd)
            self._fan_fd = None

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def marked_mounts(self) -> list[str]:
        return list(self._marked_mounts)

    def last_error(self) -> Optional[str]:
        return self._error

    # ── internals ────────────────────────────────────────────────────────

    def _should_ignore(self, path: Optional[str]) -> bool:
        if path is None:
            return False
        rp = os.path.realpath(path)
        return any(rp == p or rp.startswith(p + os.sep) for p in self.ignore_prefixes)

    def _read_loop(self):
        assert self._fan_fd is not None
        buf_size = 4096
        while not self._stop_event.is_set():
            try:
                r, _, _ = select.select([self._fan_fd], [], [], 0.5)
            except OSError:
                break  # fd closed out from under us during shutdown
            if not r:
                continue
            try:
                data = os.read(self._fan_fd, buf_size)
            except BlockingIOError:
                continue
            except OSError:
                break
            offset = 0
            while offset + _META_SIZE <= len(data):
                try:
                    event_len, vers, _reserved, metadata_len, mask, fd, pid = \
                        struct.unpack_from(_META_FMT, data, offset)
                except struct.error:
                    break  # truncated record — drop the rest of this read
                next_offset = offset + (event_len if event_len >= _META_SIZE else _META_SIZE)

                try:
                    if mask & FAN_Q_OVERFLOW:
                        pass  # kernel dropped events under load — nothing to resolve
                    elif pid != self._self_pid:  # never report our own opens
                        self._handle_one(fd, pid)
                finally:
                    if fd is not None and fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                offset = next_offset
                if event_len < _META_SIZE:
                    break  # malformed — avoid an infinite loop on this buffer

    def _handle_one(self, fd: int, pid: int):
        ts = time.time()
        file_path: Optional[str] = None
        if fd >= 0:
            try:
                file_path = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                file_path = None

        if self._should_ignore(file_path):
            return

        comm, exe_path = _proc_name(pid)
        ev = FileOpenEvent(
            pid=pid, process_name=comm, exe_path=exe_path,
            file_path=file_path, ts=ts,
        )
        try:
            self.callback(ev)
        except Exception:
            pass  # a bad callback must never kill the reader thread


# ─── Self-test — skips (not fails) when not root/not Linux ────────────────

def _run_self_test():
    import subprocess as sp
    import tempfile

    ok, reason = is_available()
    print(f"[availability] {reason}")
    if not ok:
        print("Skipping live checks — requires root on Linux with kernel >= 4.20.")
        print("Run: sudo python3 fanotify_watcher.py")
        return

    tmp = tempfile.mkdtemp()
    received: list[FileOpenEvent] = []
    lock = threading.Lock()

    def cb(ev: FileOpenEvent):
        with lock:
            received.append(ev)

    print("[1/2] marking filesystem + detecting a write from another process ... ", end="", flush=True)
    w = FanotifyWatcher(mounts=[tmp], callback=cb)
    w.start()
    time.sleep(0.2)
    target = os.path.join(tmp, "probe.txt")
    # Use a real child process (not this interpreter) so pid != self._self_pid.
    sp.run(["/bin/sh", "-c", f"echo hi > {target}"], check=True)
    time.sleep(0.5)
    with lock:
        hit = any(e.file_path and os.path.realpath(e.file_path) == os.path.realpath(target)
                  for e in received)
    assert hit, f"expected an open() event for {target}, got {[e.file_path for e in received]}"
    print("OK")
    w.stop()

    print("[2/2] ignore_prefixes suppresses events under that specific path ... ", end="", flush=True)
    with lock:
        received.clear()
    w2 = FanotifyWatcher(mounts=[tmp], callback=cb, ignore_prefixes=[tmp])
    w2.start()
    time.sleep(0.2)
    sp.run(["/bin/sh", "-c", f"echo hi2 > {target}"], check=True)
    time.sleep(0.5)
    with lock:
        # Note: FAN_MARK_FILESYSTEM covers the whole mount `tmp` lives on —
        # in some containers/overlayfs setups that's the SAME mount as
        # /usr, /etc, etc., so unrelated events (e.g. /bin/sh loading its
        # own libs) can legitimately show up here too. That's correct
        # "any folder, anywhere" behavior, not a bug — this check only
        # confirms the *target* path itself was suppressed.
        hit = any(e.file_path and os.path.realpath(e.file_path) == os.path.realpath(target)
                  for e in received)
    assert not hit, f"expected {target} to be suppressed by ignore_prefixes, but it was reported"
    print("OK")
    w2.stop()

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print("\nAll checks passed.")


if __name__ == "__main__":
    _run_self_test()
