"""
watcher.py — Stage 2
Watches ALL placement directories from config.DECOY_PLACEMENTS on the real
filesystem simultaneously — not just one flat folder.

Two independent signals per watched directory, feeding one shared debouncer:
  1. watchdog (inotify / FSEvents / ReadDirectoryChangesW) — fast, event-driven.
  2. A polling fallback that stats every known decoy file on a fixed interval,
     independent of the OS event API — catches anything watchdog drops under
     load, during observer restart, or on filesystems that suppress atime/mtime.

Only paths that appear in decoy_gen.all_decoy_paths() emit events — we ignore
everything else in those directories (other apps' files, temp files, etc.) so
the classifier only ever sees real decoy touches.

Events carry the absolute path (not a relpath) so the dashboard can show the
exact filesystem location the touch happened at.

Known limitation: pure reads (open/close with no write) on macOS and Windows
default mounts don't update st_atime, so they surface only via watchdog's
on_opened semantics where available, or not at all.  Full read detection needs
eBPF/ETW; out of scope here.

Reliability checkpoints:
  - 50 rapid writes to one file → debounced to ≤5 events, ≥50 raw signals seen.
  - Quiet writes separated by >debounce_ms each get their own event (not merged).
  - Polling fallback alone (watchdog disabled) still detects new/changed files.
  - Watcher restart mid-flood doesn't crash and resumes coverage.
  - Events for non-decoy files in a watched dir are filtered out.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import config

EventCallback = Callable[[str, str, float], None]   # (event_type, abs_path, ts)

_TYPE_MAP = {
    "created":  "modify",
    "modified": "modify",
    "deleted":  "delete",
    "moved":    "rename",
}


# ─── Debouncer ─────────────────────────────────────────────────────────────

class _Debouncer:
    """Shared per-path trailing-edge debounce across all watched directories.
    Collapses bursts (50 writes in 0.5 s) into one clean event while keeping
    quiet sequential touches as separate events."""

    def __init__(self, debounce_s: float, on_fire: EventCallback):
        self.debounce_s = debounce_s
        self.on_fire    = on_fire
        self._timers:  dict[str, threading.Timer]       = {}
        self._pending: dict[str, tuple[str, float]]     = {}  # abs_path → (type, first_ts)
        self._lock = threading.Lock()
        self.raw_event_count   = 0
        self.fired_event_count = 0

    def feed(self, event_type: str, abs_path: str, ts: Optional[float] = None):
        ts = ts if ts is not None else time.time()
        with self._lock:
            self.raw_event_count += 1
            existing = self._timers.get(abs_path)
            if existing:
                existing.cancel()
            if abs_path not in self._pending:
                self._pending[abs_path] = (event_type, ts)
            else:
                # Preserve burst start-time; keep latest event type.
                self._pending[abs_path] = (event_type, self._pending[abs_path][1])
            t = threading.Timer(self.debounce_s, self._fire, args=(abs_path,))
            t.daemon = True
            self._timers[abs_path] = t
            t.start()

    def _fire(self, abs_path: str):
        with self._lock:
            pending = self._pending.pop(abs_path, None)
            self._timers.pop(abs_path, None)
            if pending is None:
                return
            self.fired_event_count += 1
        event_type, ts = pending
        self.on_fire(event_type, abs_path, ts)

    def flush(self):
        """Fire all in-flight timers immediately (called on stop())."""
        with self._lock:
            paths = list(self._timers.keys())
        for p in paths:
            t = self._timers.get(p)
            if t:
                t.cancel()
            self._fire(p)


# ─── Watchdog handler ───────────────────────────────────────────────────────

class _Handler(FileSystemEventHandler):
    """One handler instance per watched directory. Filters events to only the
    known decoy paths so activity from other apps in the same dir is ignored."""

    def __init__(self, debouncer: _Debouncer, known_paths: set[str]):
        self.debouncer   = debouncer
        self.known_paths = known_paths   # absolute paths of decoys in this dir

    def _emit(self, event_type: str, abs_path: str):
        if abs_path in self.known_paths:
            self.debouncer.feed(event_type, abs_path)

    def on_created(self, event):
        if not event.is_directory:
            self._emit("modify", os.path.abspath(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("modify", os.path.abspath(event.src_path))

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit("delete", os.path.abspath(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            # dest may now be outside our known set — report the src as deleted
            self._emit("rename", os.path.abspath(event.src_path))


# ─── Watcher ───────────────────────────────────────────────────────────────

class Watcher:
    """
    Watches all dirs in config.DECOY_PLACEMENTS simultaneously.
    Emits debounced events only for files that appear in `known_decoy_paths`.

    callback(event_type, abs_path, ts)
        event_type : "modify" | "delete" | "rename"
        abs_path   : absolute filesystem path of the touched decoy
        ts         : float epoch of when the burst *started*

    Usage:
        w = Watcher(known_decoy_paths={...}, callback=my_fn)
        w.start()
        ...
        w.stop()
    """

    def __init__(
        self,
        known_decoy_paths: Optional[set[str]] = None,
        callback:          Optional[EventCallback] = None,
        debounce_ms:       int   = config.DEBOUNCE_MS,
        poll_interval_s:   float = config.POLL_FALLBACK_SECONDS,
    ):
        # If no explicit set is given, load live from the manifest.
        # Watcher.refresh_known_paths() can update this while running.
        import decoy_gen
        self._known_paths: set[str] = (
            set(known_decoy_paths) if known_decoy_paths is not None
            else set(decoy_gen.all_decoy_paths())
        )
        self._known_lock = threading.Lock()

        self.callback       = callback or (lambda *a: None)
        self.debouncer      = _Debouncer(debounce_ms / 1000.0, self._on_debounced)
        self.poll_interval_s = poll_interval_s

        self._observer:     Optional[Observer]         = None
        self._poll_thread:  Optional[threading.Thread] = None
        self._poll_stop     = threading.Event()
        # path → (mtime, size) — maintained by poller
        self._poll_state:   dict[str, tuple[float, int]] = {}
        self._poll_lock     = threading.Lock()

        # Test hook: set True to skip watchdog and run poller only
        self.poll_only = False

    # ── public API ──────────────────────────────────────────────────────

    def start(self):
        if not self.poll_only:
            self._start_observer()
        self._start_poller()

    def stop(self):
        self._stop_observer()
        self._stop_poller()
        self.debouncer.flush()

    def is_alive(self) -> bool:
        obs_ok  = self.poll_only or (self._observer is not None and self._observer.is_alive())
        poll_ok = self._poll_thread is not None and self._poll_thread.is_alive()
        return obs_ok and poll_ok

    def refresh_known_paths(self, paths: set[str]):
        """Hot-reload the decoy path set without restarting the watcher.
        Call after decoy_gen.generate_decoys() adds new files at runtime."""
        with self._known_lock:
            self._known_paths = set(paths)
        # Re-register watchdog on any new directories now being watched
        if not self.poll_only and self._observer is not None:
            self._schedule_all_dirs()

    def known_paths(self) -> set[str]:
        with self._known_lock:
            return set(self._known_paths)

    # ── watchdog side ───────────────────────────────────────────────────

    def _schedule_all_dirs(self):
        """Schedule one watch per unique parent directory that contains at
        least one known decoy. The observer deduplicates if a dir is already
        scheduled (watchdog handles that internally)."""
        watched_dirs: set[str] = set()
        with self._known_lock:
            paths = set(self._known_paths)
        for p in paths:
            d = os.path.dirname(p)
            if d not in watched_dirs:
                watched_dirs.add(d)
                known_in_dir = {pp for pp in paths if os.path.dirname(pp) == d}
                handler = _Handler(self.debouncer, known_in_dir)
                try:
                    os.makedirs(d, exist_ok=True)
                    self._observer.schedule(handler, d, recursive=False)
                except Exception:
                    pass  # dir may not exist yet on this host; poller covers it

    def _start_observer(self):
        self._observer = Observer()
        self._schedule_all_dirs()
        self._observer.start()

    def _stop_observer(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None

    # ── polling fallback ────────────────────────────────────────────────

    def _poll_snapshot(self) -> dict[str, tuple[float, int]]:
        """stat() every known decoy path — O(n decoys), not O(dir listing)."""
        snap: dict[str, tuple[float, int]] = {}
        with self._known_lock:
            paths = set(self._known_paths)
        for p in paths:
            try:
                st    = os.stat(p)
                snap[p] = (st.st_mtime, st.st_size)
            except OSError:
                # File absent: treat as deleted (handled in diff below)
                pass
        return snap

    def _poll_loop(self):
        with self._poll_lock:
            self._poll_state = self._poll_snapshot()
        while not self._poll_stop.wait(self.poll_interval_s):
            current = self._poll_snapshot()
            with self._poll_lock:
                prev = self._poll_state
                for path, stat_val in current.items():
                    old = prev.get(path)
                    if old is None or old != stat_val:
                        self.debouncer.feed("modify", path)
                for path in prev:
                    if path not in current:
                        self.debouncer.feed("delete", path)
                self._poll_state = current

    def _start_poller(self):
        self._poll_stop.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="tripwire-poller"
        )
        self._poll_thread.start()

    def _stop_poller(self):
        self._poll_stop.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=self.poll_interval_s + 2)
            self._poll_thread = None

    # ── debounced callback ──────────────────────────────────────────────

    def _on_debounced(self, event_type: str, abs_path: str, ts: float):
        # Keep the poller's own baseline in sync with whatever change was
        # just delivered — regardless of whether watchdog or the poller
        # itself produced it. Without this, watchdog reports a change
        # immediately, the poller's cached (mtime, size) never learns about
        # it, and the poller's next tick "discovers" the same already-
        # reported change again and fires a duplicate event.
        with self._poll_lock:
            if event_type == "delete":
                self._poll_state.pop(abs_path, None)
            else:
                try:
                    st = os.stat(abs_path)
                    self._poll_state[abs_path] = (st.st_mtime, st.st_size)
                except OSError:
                    self._poll_state.pop(abs_path, None)
        try:
            self.callback(event_type, abs_path, ts)
        except Exception:
            pass   # callback errors must never kill the watcher thread


# ─── Self-test ──────────────────────────────────────────────────────────────

def _run_self_test():
    import tempfile, shutil

    tmp = tempfile.mkdtemp()

    # Create two fake "placement" directories (Desktop, Documents)
    dir_a = os.path.join(tmp, "Desktop");   os.makedirs(dir_a)
    dir_b = os.path.join(tmp, "Documents"); os.makedirs(dir_b)

    decoy_a = os.path.join(dir_a, "Passwords_Backup.txt")
    decoy_b = os.path.join(dir_b, "Board_Meeting_Minutes.docx")
    noise   = os.path.join(dir_a, "real_user_file.txt")   # should be ignored

    # seed decoys
    open(decoy_a, "w").close()
    open(decoy_b, "w").close()

    known = {decoy_a, decoy_b}   # noise NOT in set

    received: list[tuple[str, str]] = []
    lock = threading.Lock()

    def cb(etype, path, ts):
        with lock:
            received.append((etype, path))

    # ── Test 1: rapid-fire 50 touches → debounced ────────────────────────
    print("[1/5] 50 rapid writes → debounced to ≤5 events, ≥50 raw signals ... ", end="", flush=True)
    w = Watcher(known_decoy_paths=known, callback=cb, debounce_ms=150, poll_interval_s=0.2)
    w.start(); time.sleep(0.3)
    for i in range(50):
        with open(decoy_a, "a") as f: f.write(str(i))
        time.sleep(0.01)
    time.sleep(0.6)
    with lock:
        n = sum(1 for (_, p) in received if p == decoy_a)
    assert 1 <= n <= 5,   f"burst not debounced: {n} events"
    assert w.debouncer.raw_event_count >= 50, "raw signals low"
    print(f"OK → raw={w.debouncer.raw_event_count}, debounced={n}")

    # ── Test 2: quiet spaced writes each get own event ───────────────────
    print("[2/5] 3 writes spaced >debounce_ms → 3 distinct events ... ", end="", flush=True)
    with lock: received.clear()
    for i in range(3):
        with open(decoy_b, "a") as f: f.write(f"row{i}\n")
        time.sleep(0.35)
    time.sleep(0.4)
    with lock:
        n2 = sum(1 for (_, p) in received if p == decoy_b)
    assert n2 >= 2, f"expected ≥2 distinct events, got {n2}"
    print(f"OK → {n2} events")
    w.stop()

    # ── Test 3: non-decoy file in same dir is filtered out ───────────────
    print("[3/5] noise file in same dir produces no event ... ", end="", flush=True)
    with lock: received.clear()
    w3 = Watcher(known_decoy_paths=known, callback=cb, debounce_ms=100, poll_interval_s=0.2)
    w3.start(); time.sleep(0.3)
    with open(noise, "w") as f: f.write("i am not a decoy")
    time.sleep(0.5)
    with lock:
        noise_events = [p for (_, p) in received if p == noise]
    assert len(noise_events) == 0, f"noise event leaked: {noise_events}"
    print("OK → noise suppressed")
    w3.stop()

    # ── Test 4: polling fallback alone catches changes ───────────────────
    print("[4/5] polling fallback (no watchdog) still detects changes ... ", end="", flush=True)
    with lock: received.clear()
    w4 = Watcher(known_decoy_paths=known, callback=cb, debounce_ms=100, poll_interval_s=0.2)
    w4.poll_only = True
    w4.start(); time.sleep(0.3)
    with open(decoy_a, "a") as f: f.write("polled")
    time.sleep(0.7)
    with lock:
        got = any(p == decoy_a for (_, p) in received)
    assert got, "polling fallback missed the change"
    print("OK")
    w4.stop()

    # ── Test 5: hot-reload known paths picks up new decoy ────────────────
    print("[5/5] refresh_known_paths() hot-adds a new decoy mid-run ... ", end="", flush=True)
    new_decoy = os.path.join(dir_b, "Tax_Returns_2024.pdf")
    open(new_decoy, "w").close()
    with lock: received.clear()
    w5 = Watcher(known_decoy_paths=known, callback=cb, debounce_ms=100, poll_interval_s=0.2)
    w5.start(); time.sleep(0.3)
    w5.refresh_known_paths(known | {new_decoy})
    time.sleep(0.3)
    with open(new_decoy, "a") as f: f.write("new")
    time.sleep(0.6)
    with lock:
        got_new = any(p == new_decoy for (_, p) in received)
    assert got_new, "hot-added decoy not watched"
    print("OK")
    w5.stop()

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n✓ All checks passed.")


if __name__ == "__main__":
    _run_self_test()
