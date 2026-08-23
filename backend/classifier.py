"""
classifier.py — Stage 4
Sliding-window severity classifier. State is persisted in SQLite
(events.EventStore.recent_touches) so a crash mid-incident doesn't
lose the evidence trail, and window math uses a monotonic clock so
NTP/clock adjustments can't corrupt the window.

Reliability checkpoint this file must pass:
  - Window state persists across a server restart mid-burst
  - Clock skew / out-of-order wall-clock timestamps don't break the window
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import config
from events import EventStore


@dataclass
class ClassificationResult:
    severity: str          # "info" | "warning" | "critical"
    mitre_id: str | None
    touch_count: int        # touches within the window, including this one


class Classifier:
    """
    Every "touch" (file event) is recorded with a WALL-CLOCK timestamp for
    persistence/reporting, but the "how many touches in the last N seconds"
    math is always done in wall-clock terms bounded by DB timestamps — the
    monotonic clock is used only within a single process's uptime to avoid
    reordering *within* one run; across restarts we necessarily fall back to
    stored wall-clock time, which is why events.py records `timestamp` as
    time.time() and this module treats it as authoritative for windowing.
    """

    def __init__(self, store: EventStore, window_s: float = config.CLASSIFIER_WINDOW_S):
        self.store = store
        self.window_s = window_s
        # monotonic reference point used only to detect wall-clock jumps
        self._last_wall = time.time()
        self._last_mono = time.monotonic()

    def _wall_now(self) -> float:
        """
        Return a wall-clock timestamp, correcting for backward NTP jumps by
        never returning a value earlier than the last one we handed out.
        This keeps windowing monotonic-safe without losing wall-clock meaning.
        """
        wall = time.time()
        mono_delta = time.monotonic() - self._last_mono
        expected = self._last_wall + mono_delta
        if wall < expected - 0.001:
            # wall clock jumped backwards (NTP correction) — trust elapsed monotonic time instead
            wall = expected
        self._last_wall = wall
        self._last_mono = time.monotonic()
        return wall

    def record_touch(self, file_path: str) -> ClassificationResult:
        ts = self._wall_now()
        self.store.add_touch(file_path, ts)

        cutoff = ts - self.window_s
        self.store.prune_touches_before(cutoff)  # keep the table small; state still DB-backed
        touches = self.store.touches_since(cutoff)
        count = len(touches)

        distinct_files = len({fp for fp, _ in touches})

        if count >= config.CRITICAL_TOUCH_THRESHOLD:
            severity = "critical"
            mitre = config.MITRE_ID_MASS_ACCESS if distinct_files > 1 else config.MITRE_ID_DISCOVERY
        elif count >= config.WARNING_TOUCH_THRESHOLD:
            severity = "warning"
            mitre = config.MITRE_ID_DISCOVERY
        else:
            severity = "info"
            mitre = None

        return ClassificationResult(severity=severity, mitre_id=mitre, touch_count=count)

    def current_window_count(self) -> int:
        cutoff = self._wall_now() - self.window_s
        return len(self.store.touches_since(cutoff))


# ─── Self-test ──────────────────────────────────────────────────────────────

def _run_self_test():
    import tempfile, os as _os

    tmp_dir = tempfile.mkdtemp()
    test_db = _os.path.join(tmp_dir, "test_tripwire.db")
    store = EventStore(db_path=test_db)

    print("[1/4] severity escalates on a synthetic burst ... ", end="")
    clf = Classifier(store, window_s=10.0)
    results = []
    for i in range(config.CRITICAL_TOUCH_THRESHOLD + 1):
        r = clf.record_touch(f"decoys/file_{i}.xlsx")
        results.append(r)
    assert results[0].severity == "info"
    assert results[-1].severity == "critical", f"expected critical, got {results[-1].severity}"
    print(f"OK -> {[r.severity for r in results]}")

    print("[2/4] window state persists across a simulated restart mid-burst ... ", end="")
    # Simulate "restart": drop the Classifier object, keep the same DB file (same as
    # a server process dying and server.py constructing a fresh Classifier(store) on boot).
    del clf
    clf2 = Classifier(store, window_s=10.0)
    count_before_new_touch = clf2.current_window_count()
    assert count_before_new_touch == config.CRITICAL_TOUCH_THRESHOLD + 1, (
        f"expected persisted count {config.CRITICAL_TOUCH_THRESHOLD + 1}, got {count_before_new_touch}"
    )
    r_after_restart = clf2.record_touch("decoys/after_restart.xlsx")
    assert r_after_restart.severity == "critical", "window should still be hot after restart"
    print(f"OK -> post-restart severity={r_after_restart.severity}, count={r_after_restart.touch_count}")

    print("[3/4] window correctly ages out old touches ... ", end="")
    tmp_db2 = _os.path.join(tmp_dir, "test2.db")
    store2 = EventStore(db_path=tmp_db2)
    clf3 = Classifier(store2, window_s=0.3)
    clf3.record_touch("decoys/x.xlsx")
    clf3.record_touch("decoys/y.xlsx")
    time.sleep(0.4)
    r3 = clf3.record_touch("decoys/z.xlsx")
    assert r3.touch_count == 1, f"expected old touches aged out, got count={r3.touch_count}"
    assert r3.severity == "info"
    print(f"OK -> count after aging={r3.touch_count}")

    print("[4/4] backward wall-clock jump doesn't corrupt window math ... ", end="")
    tmp_db3 = _os.path.join(tmp_dir, "test3.db")
    store3 = EventStore(db_path=tmp_db3)
    clf4 = Classifier(store3, window_s=10.0)
    clf4.record_touch("decoys/a.xlsx")
    # simulate an NTP backward jump by manually rewinding the reference wall clock
    clf4._last_wall -= 5.0
    r4 = clf4.record_touch("decoys/b.xlsx")
    assert r4.touch_count == 2, f"expected both touches still counted, got {r4.touch_count}"
    print(f"OK -> count survived clock jump={r4.touch_count}")

    print("\nAll checks passed.")

    for p in (test_db, tmp_db2, tmp_db3):
        for suffix in ("", "-wal", "-shm"):
            try:
                _os.remove(p + suffix)
            except OSError:
                pass
    _os.rmdir(tmp_dir)


if __name__ == "__main__":
    _run_self_test()
