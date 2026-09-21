"""
fanotify_watcher.py — full-system file-change audit.

Fanotify is used when available. On Termux/Android, where fanotify is not
available, Linux inotify is used automatically.

Only genuine filesystem manipulation is emitted:
- write/modify
- delete
- rename/move

Read-only opens are ignored.

Windows is intentionally unsupported.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno as _errno
import os
import select
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


# ─── fanotify constants ─────────────────────────────────────────────────────

FAN_CLASS_NOTIF     = 0x00000000
FAN_CLOEXEC         = 0x00000001
FAN_NONBLOCK        = 0x00000002
FAN_MARK_ADD        = 0x00000001
FAN_MARK_FILESYSTEM = 0x00000100

FAN_ACCESS      = 0x00000001
FAN_CLOSE_WRITE = 0x00000008
FAN_DELETE      = 0x00000200
FAN_MOVED_FROM  = 0x00000040
FAN_MOVED_TO    = 0x00000080
FAN_Q_OVERFLOW  = 0x00004000

AT_FDCWD = -100

_META_FMT = "=IBBHqii"
_META_SIZE = struct.calcsize(_META_FMT)
assert _META_SIZE == 24


# ─── inotify constants ─────────────────────────────────────────────────────

IN_ACCESS      = 0x00000001
IN_MODIFY      = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM  = 0x00000040
IN_MOVED_TO    = 0x00000080
IN_CREATE      = 0x00000100
IN_DELETE      = 0x00000200
IN_Q_OVERFLOW  = 0x00004000
IN_ISDIR       = 0x40000000

_INOTIFY_FMT = "=iIII"
_INOTIFY_SIZE = struct.calcsize(_INOTIFY_FMT)

IN_NONBLOCK = 0x00000800


@dataclass
class FileOpenEvent:
    pid: int
    process_name: str
    exe_path: Optional[str]
    file_path: Optional[str]
    ts: float

    # Backward-compatible additional information.
    # Existing consumers can simply ignore this field.
    action: str = "modified"


EventCallback = Callable[[FileOpenEvent], None]


def _load_libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c")

    if not name:
        raise OSError("could not locate libc")

    libc = ctypes.CDLL(name, use_errno=True)

    # Fanotify
    if hasattr(libc, "fanotify_init"):
        libc.fanotify_init.restype = ctypes.c_int
        libc.fanotify_init.argtypes = [
            ctypes.c_uint,
            ctypes.c_uint,
        ]

    if hasattr(libc, "fanotify_mark"):
        libc.fanotify_mark.restype = ctypes.c_int
        libc.fanotify_mark.argtypes = [
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.c_char_p,
        ]

    # Inotify
    if hasattr(libc, "inotify_init1"):
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_init1.argtypes = [ctypes.c_int]

    elif hasattr(libc, "inotify_init"):
        libc.inotify_init.restype = ctypes.c_int
        libc.inotify_init.argtypes = []

    if hasattr(libc, "inotify_add_watch"):
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]

    return libc


def _fanotify_available() -> tuple[bool, str]:

    if os.name != "posix" or not os.path.exists("/proc"):
        return False, "fanotify is Linux-only"

    try:
        libc = _load_libc()
    except OSError as e:
        return False, str(e)

    if not hasattr(libc, "fanotify_init"):
        return False, "kernel/libc does not expose fanotify"

    fd = libc.fanotify_init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
        os.O_RDONLY,
    )

    if fd < 0:
        err = ctypes.get_errno()

        if err in (_errno.EPERM, _errno.EACCES):
            return False, (
                "fanotify unavailable: permission denied "
                "(CAP_SYS_ADMIN/root required)"
            )

        if err == _errno.ENOSYS:
            return False, "fanotify unavailable: kernel does not provide fanotify"

        return False, f"fanotify_init failed (errno={err})"

    try:
        mask = (
            FAN_CLOSE_WRITE
            | FAN_DELETE
            | FAN_MOVED_FROM
            | FAN_MOVED_TO
        )

        rc = libc.fanotify_mark(
            fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            mask,
            AT_FDCWD,
            b"/",
        )

        if rc < 0:
            err = ctypes.get_errno()

            if err in (
                _errno.EOPNOTSUPP,
                _errno.ENOSYS,
                _errno.EINVAL,
            ):
                return False, (
                    f"fanotify filesystem marking unavailable (errno={err})"
                )

            return False, f"fanotify_mark failed (errno={err})"

    finally:
        os.close(fd)

    return True, "ok"


def _inotify_available() -> tuple[bool, str]:

    if os.name != "posix":
        return False, "inotify is Linux/Android only"

    try:
        libc = _load_libc()

        if (
            not hasattr(libc, "inotify_init1")
            and not hasattr(libc, "inotify_init")
        ):
            return False, "inotify is unavailable in libc"

        if not hasattr(libc, "inotify_add_watch"):
            return False, "inotify_add_watch is unavailable in libc"

        if hasattr(libc, "inotify_init1"):
            fd = libc.inotify_init1(IN_NONBLOCK)
        else:
            fd = libc.inotify_init()

            if fd >= 0:
                os.set_blocking(fd, False)

        if fd < 0:
            return False, (
                f"inotify_init failed "
                f"(errno={ctypes.get_errno()})"
            )

        os.close(fd)

        return True, "ok"

    except OSError as e:
        return False, str(e)


def is_available() -> tuple[bool, str]:
    """
    Fanotify is preferred.

    If fanotify is unavailable, inotify is used automatically.
    This is the mode used by normal Termux installations.
    """

    fan_ok, fan_reason = _fanotify_available()

    if fan_ok:
        return True, "fanotify"

    ino_ok, ino_reason = _inotify_available()

    if ino_ok:
        return True, f"inotify fallback ({fan_reason})"

    return False, (
        f"fanotify unavailable ({fan_reason}); "
        f"inotify unavailable ({ino_reason})"
    )


def _proc_name(pid: int) -> tuple[str, Optional[str]]:

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
    Stable public API.

    Linux:
        fanotify when available.

    Termux/Android:
        automatic inotify fallback.

    Windows:
        unsupported.
    """

    def __init__(
        self,
        mounts: list[str],
        callback: Optional[EventCallback] = None,
        event_mask: int = (
            FAN_CLOSE_WRITE
            | FAN_DELETE
            | FAN_MOVED_FROM
            | FAN_MOVED_TO
        ),
        ignore_prefixes: Optional[list[str]] = None,
    ):

        if not mounts:
            raise ValueError(
                "FanotifyWatcher needs at least one mount/path to mark"
            )

        self.mounts = list(mounts)

        self.callback = (
            callback
            if callback is not None
            else lambda *_a, **_kw: None
        )

        self.event_mask = event_mask

        self.ignore_prefixes = [
            os.path.realpath(p)
            for p in (ignore_prefixes or [])
        ]

        self._self_pid = os.getpid()

        self._libc: Optional[ctypes.CDLL] = None

        self._fan_fd: Optional[int] = None
        self._ino_fd: Optional[int] = None

        self._thread: Optional[threading.Thread] = None

        self._stop_event = threading.Event()

        self._marked_mounts: list[str] = []

        self._ino_watches: dict[int, str] = {}
        self._ino_lock = threading.Lock()

        self._error: Optional[str] = None

        self.backend = "unstarted"

    # ──────────────────────────────────────────────────────────────────────
    # Start
    # ──────────────────────────────────────────────────────────────────────

    def start(self):

        ok, reason = is_available()

        if not ok:
            self._error = reason
            raise PermissionError(
                f"cannot start FanotifyWatcher: {reason}"
            )

        self._libc = _load_libc()

        fan_ok, _ = _fanotify_available()

        self._stop_event.clear()

        if fan_ok:

            try:
                self._start_fanotify()
                self.backend = "fanotify"

            except (OSError, PermissionError) as e:

                self._error = (
                    f"fanotify start failed: {e}; "
                    "trying inotify fallback"
                )

                self._close_fan_fd()

                self._start_inotify()
                self.backend = "inotify"

        else:

            self._start_inotify()
            self.backend = "inotify"
            self._error = reason

        self._thread = threading.Thread(
            target=self._read_loop,
            daemon=True,
            name="tripwire-fanotify",
        )

        self._thread.start()

    # ──────────────────────────────────────────────────────────────────────
    # Fanotify
    # ──────────────────────────────────────────────────────────────────────

    def _start_fanotify(self):

        assert self._libc is not None

        fd = self._libc.fanotify_init(
            FAN_CLASS_NOTIF
            | FAN_CLOEXEC
            | FAN_NONBLOCK,
            os.O_RDONLY
            | getattr(os, "O_LARGEFILE", 0),
        )

        if fd < 0:
            raise OSError(
                f"fanotify_init failed "
                f"(errno={ctypes.get_errno()})"
            )

        self._fan_fd = fd
        self._marked_mounts = []

        for mount in self.mounts:

            rc = self._libc.fanotify_mark(
                self._fan_fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                self.event_mask,
                AT_FDCWD,
                os.fsencode(mount),
            )

            if rc < 0:

                self._error = (
                    f"failed to mark {mount!r} "
                    f"(errno={ctypes.get_errno()})"
                )

                continue

            self._marked_mounts.append(mount)

        if not self._marked_mounts:

            self._close_fan_fd()

            raise OSError(
                self._error or "no mount could be marked"
            )

    # ──────────────────────────────────────────────────────────────────────
    # Inotify / Termux
    # ──────────────────────────────────────────────────────────────────────

    def _start_inotify(self):

        assert self._libc is not None

        if hasattr(self._libc, "inotify_init1"):

            fd = self._libc.inotify_init1(IN_NONBLOCK)

        else:

            fd = self._libc.inotify_init()

            if fd >= 0:
                os.set_blocking(fd, False)

        if fd < 0:
            raise OSError(
                f"inotify_init failed "
                f"(errno={ctypes.get_errno()})"
            )

        self._ino_fd = fd

        with self._ino_lock:
            self._ino_watches.clear()

        self._marked_mounts = []

        for root in self.mounts:

            root = os.path.realpath(root)

            if not os.path.isdir(root):
                continue

            self._add_inotify_tree(root)

            with self._ino_lock:
                has_watch = any(
                    path == root
                    or path.startswith(root + os.sep)
                    for path in self._ino_watches.values()
                )

            if has_watch:
                self._marked_mounts.append(root)

        if not self._ino_watches:

            self._close_ino_fd()

            raise OSError(
                "no directory could be watched with inotify"
            )

    def _add_inotify_tree(self, root: str):

        if self._ino_fd is None:
            return

        if not os.path.isdir(root):
            return

        try:

            for base, dirs, _files in os.walk(
                root,
                topdown=True,
                followlinks=False,
            ):

                dirs[:] = [
                    d
                    for d in dirs
                    if not self._should_ignore(
                        os.path.join(base, d)
                    )
                ]

                self._add_inotify_dir(base)

        except OSError as exc:

            self._error = (
                f"inotify directory scan warning: {exc}"
            )

    def _add_inotify_dir(self, path: str):

        if self._ino_fd is None:
            return

        if self._should_ignore(path):
            return

        mask = (
            IN_CLOSE_WRITE
            | IN_DELETE
            | IN_MOVED_FROM
            | IN_MOVED_TO
            | IN_CREATE
        )

        wd = self._libc.inotify_add_watch(
            self._ino_fd,
            os.fsencode(path),
            mask,
        )

        if wd >= 0:

            with self._ino_lock:
                self._ino_watches[wd] = path

    # ──────────────────────────────────────────────────────────────────────
    # Stop / state
    # ──────────────────────────────────────────────────────────────────────

    def stop(self):

        self._stop_event.set()

        if self._thread:

            self._thread.join(timeout=2)
            self._thread = None

        self._close_fan_fd()
        self._close_ino_fd()

        with self._ino_lock:
            self._ino_watches.clear()

    def _close_fan_fd(self):

        if self._fan_fd is not None:

            try:
                os.close(self._fan_fd)
            except OSError:
                pass

            self._fan_fd = None

    def _close_ino_fd(self):

        if self._ino_fd is not None:

            try:
                os.close(self._ino_fd)
            except OSError:
                pass

            self._ino_fd = None

    def is_alive(self) -> bool:

        return (
            self._thread is not None
            and self._thread.is_alive()
        )

    def marked_mounts(self) -> list[str]:

        return list(self._marked_mounts)

    def last_error(self) -> Optional[str]:

        return self._error

    # ──────────────────────────────────────────────────────────────────────
    # Ignore paths
    # ──────────────────────────────────────────────────────────────────────

    def _should_ignore(
        self,
        path: Optional[str],
    ) -> bool:

        if path is None:
            return False

        rp = os.path.realpath(path)

        return any(
            rp == prefix
            or rp.startswith(prefix + os.sep)
            for prefix in self.ignore_prefixes
        )

    # ──────────────────────────────────────────────────────────────────────
    # Main read loop
    # ──────────────────────────────────────────────────────────────────────

    def _read_loop(self):

        if self.backend == "fanotify":
            self._fanotify_loop()
        else:
            self._inotify_loop()

    # ──────────────────────────────────────────────────────────────────────
    # Fanotify event loop
    # ──────────────────────────────────────────────────────────────────────

    def _fanotify_loop(self):

        assert self._fan_fd is not None

        while not self._stop_event.is_set():

            try:

                r, _, _ = select.select(
                    [self._fan_fd],
                    [],
                    [],
                    0.5,
                )

            except OSError:
                break

            if not r:
                continue

            try:
                data = os.read(
                    self._fan_fd,
                    65536,
                )

            except BlockingIOError:
                continue

            except OSError:
                break

            offset = 0

            while offset + _META_SIZE <= len(data):

                try:

                    (
                        event_len,
                        _vers,
                        _reserved,
                        _metadata_len,
                        mask,
                        fd,
                        pid,
                    ) = struct.unpack_from(
                        _META_FMT,
                        data,
                        offset,
                    )

                except struct.error:
                    break

                next_offset = offset + (
                    event_len
                    if event_len >= _META_SIZE
                    else _META_SIZE
                )

                try:

                    if (
                        not (mask & FAN_Q_OVERFLOW)
                        and pid != self._self_pid
                    ):

                        if mask & (
                            FAN_CLOSE_WRITE
                            | FAN_DELETE
                            | FAN_MOVED_FROM
                            | FAN_MOVED_TO
                        ):

                            self._handle_fan_event(
                                fd,
                                pid,
                                mask,
                            )

                finally:

                    if fd >= 0:

                        try:
                            os.close(fd)
                        except OSError:
                            pass

                offset = next_offset

                if event_len < _META_SIZE:
                    break

    def _handle_fan_event(
        self,
        fd: int,
        pid: int,
        mask: int,
    ):

        file_path = None

        if fd >= 0:

            try:
                file_path = os.readlink(
                    f"/proc/self/fd/{fd}"
                )
            except OSError:
                pass

        if self._should_ignore(file_path):
            return

        comm, exe_path = _proc_name(pid)

        if mask & FAN_DELETE:
            action = "deleted"

        elif mask & (
            FAN_MOVED_FROM
            | FAN_MOVED_TO
        ):
            action = "renamed"

        else:
            action = "modified"

        self._emit(
            FileOpenEvent(
                pid,
                comm,
                exe_path,
                file_path,
                time.time(),
                action,
            )
        )

    # ──────────────────────────────────────────────────────────────────────
    # Inotify event loop
    # ──────────────────────────────────────────────────────────────────────

    def _inotify_loop(self):

        assert self._ino_fd is not None

        while not self._stop_event.is_set():

            try:

                r, _, _ = select.select(
                    [self._ino_fd],
                    [],
                    [],
                    0.5,
                )

            except OSError:
                break

            if not r:
                continue

            try:

                data = os.read(
                    self._ino_fd,
                    65536,
                )

            except BlockingIOError:
                continue

            except OSError:
                break

            offset = 0

            while offset + _INOTIFY_SIZE <= len(data):

                try:

                    (
                        wd,
                        mask,
                        _cookie,
                        name_len,
                    ) = struct.unpack_from(
                        _INOTIFY_FMT,
                        data,
                        offset,
                    )

                except struct.error:
                    break

                end = (
                    offset
                    + _INOTIFY_SIZE
                    + name_len
                )

                if end > len(data):
                    break

                raw_name = data[
                    offset + _INOTIFY_SIZE:end
                ]

                name = raw_name.split(
                    b"\0",
                    1,
                )[0].decode(
                    errors="surrogateescape"
                )

                offset = end

                if mask & IN_Q_OVERFLOW:
                    continue

                with self._ino_lock:
                    base = self._ino_watches.get(wd)

                if not base:
                    continue

                path = (
                    os.path.join(base, name)
                    if name
                    else base
                )

                if self._should_ignore(path):
                    continue

                if mask & IN_ISDIR:

                    self._handle_inotify_dir(
                        wd,
                        mask,
                        name,
                    )

                    continue

                # IMPORTANT:
                #
                # IN_MODIFY alone is ignored.
                #
                # IN_CLOSE_WRITE means that the file was
                # actually opened for writing and closed.
                #
                # Therefore ordinary read-only opens do not
                # generate TripWire manipulation events.

                if mask & IN_CLOSE_WRITE:

                    self._emit(
                        self._fallback_event(
                            path,
                            "modified",
                        )
                    )

                elif mask & IN_DELETE:

                    self._emit(
                        self._fallback_event(
                            path,
                            "deleted",
                        )
                    )

                elif mask & (
                    IN_MOVED_FROM
                    | IN_MOVED_TO
                ):

                    self._emit(
                        self._fallback_event(
                            path,
                            "renamed",
                        )
                    )

    def _handle_inotify_dir(
        self,
        wd: int,
        mask: int,
        name: str,
    ):

        with self._ino_lock:
            base = self._ino_watches.get(wd)

        if not base or not name:
            return

        path = os.path.join(
            base,
            name,
        )

        if (
            mask & (
                IN_CREATE
                | IN_MOVED_TO
            )
            and os.path.isdir(path)
            and not self._should_ignore(path)
        ):

            self._add_inotify_tree(path)

    # ──────────────────────────────────────────────────────────────────────
    # Fallback event
    # ──────────────────────────────────────────────────────────────────────

    def _fallback_event(
        self,
        path: str,
        action: str,
    ) -> FileOpenEvent:

        # inotify does not provide the originating process PID.
        # Never guess the process.
        return FileOpenEvent(
            pid=-1,
            process_name="unavailable (inotify)",
            exe_path=None,
            file_path=path,
            ts=time.time(),
            action=action,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Callback
    # ──────────────────────────────────────────────────────────────────────

    def _emit(
        self,
        ev: FileOpenEvent,
    ):

        try:
            self.callback(ev)

        except Exception as exc:

            # Do not silently hide integration errors.
            self._error = (
                f"watcher callback failed: {exc}"
            )


# ─── self-test ─────────────────────────────────────────────────────────────

def _run_self_test():

    import shutil
    import subprocess as sp
    import tempfile

    ok, reason = is_available()

    print(f"[availability] {reason}")

    if not ok:

        print(
            "No supported Linux watcher is available here."
        )

        return

    tmp = tempfile.mkdtemp()

    received: list[FileOpenEvent] = []

    lock = threading.Lock()

    def cb(ev: FileOpenEvent):

        with lock:
            received.append(ev)

    try:

        watcher = FanotifyWatcher(
            [tmp],
            callback=cb,
        )

        watcher.start()

        print(
            f"[backend] {watcher.backend}"
        )

        target = os.path.join(
            tmp,
            "probe.txt",
        )

        sp.run(
            [
                "/bin/sh",
                "-c",
                f"echo hi > '{target}'",
            ],
            check=True,
        )

        time.sleep(0.5)

        with lock:

            hit = any(
                e.file_path
                and os.path.realpath(e.file_path)
                == os.path.realpath(target)
                and e.action == "modified"
                for e in received
            )

        assert hit, (
            f"expected a write event for {target}"
        )

        print(
            "[1/2] write/modify detection: OK"
        )

        before = len(received)

        with open(target, "r") as f:
            f.read()

        time.sleep(0.2)

        with lock:
            after = len(received)

        assert after == before, (
            "read-only open incorrectly generated "
            "a manipulation event"
        )

        print(
            "[2/2] read-only opens are not emitted "
            "as change events: OK"
        )

        watcher.stop()

    finally:

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )


if __name__ == "__main__":
    _run_self_test()
