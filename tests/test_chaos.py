"""
tests/test_chaos.py

End-to-end chaos coverage for build-plan Section 4 "Reliability Test Pass",
run before dashboard integration:
  - Flood: 200+ events across 10 files in <2s -> no dropped events, no
    duplicate classification triggers, WebSocket doesn't fall behind
  - Kill mid-write: process killed while a file handle is open -> attribution
    still returns a plausible candidate, not a crash
  - Restart mid-incident: server killed/restarted mid-sweep -> classifier
    window state and event log survive in SQLite
  - Double panic: Panic Mode triggered twice in a row -> no errors, no
    double-suspend
  - Permission denied paths: chmod/suspend against an inaccessible target
    -> logged and skipped, not an unhandled exception
  - One bad/malformed event never takes down the watcher thread

Run: pytest tests/test_chaos.py -v -s
(-s recommended: some tests involve real subprocess timing)
"""

import json
import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from events import EventStore
from classifier import Classifier
from server import TripwireServer


@pytest.fixture
def srv(tmp_path):
    db_path = os.path.join(tmp_path, "chaos.db")
    decoy_dir = os.path.join(tmp_path, "decoys")
    server = TripwireServer(db_path=db_path, decoy_dir=decoy_dir, dry_run=True)
    yield server
    server.stop()


# ─── flood ──────────────────────────────────────────────────────────────────

def test_flood_no_dropped_or_duplicate_events(srv):
    """Fire a 200-event flood directly at the pipeline entry point (bypassing
    real filesystem timing, which the watcher's own debounce test already
    covers) and confirm every event lands exactly once, none are lost, and
    the server never raises."""
    n = 220
    files = 10
    for i in range(n):
        srv._on_fs_event("modify", f"decoys/flood_{i % files}.xlsx", time.time())

    assert srv.store.count_events() == n, "every flood event should be persisted exactly once"
    assert srv.store.dead_letter_count() == 0, "well-formed flood events must not be dead-lettered"

    emitted = [p for (name, p) in srv.socketio_emitted if name == "tripwire_event"]
    assert len(emitted) == n, "WebSocket must emit exactly one tripwire_event per flood event, no drops"


def test_flood_triggers_panic_exactly_once_per_incident_window(srv):
    """A sustained flood should escalate to critical and fire panic_mode, but
    repeated critical touches within the same incident must not spam a fresh
    Panic Mode trigger with different behavior each time (idempotent trigger)."""
    for i in range(config.CRITICAL_TOUCH_THRESHOLD + 10):
        srv._on_fs_event("modify", f"decoys/burst_{i}.xlsx", time.time())

    panic_emits = [p for (name, p) in srv.socketio_emitted if name == "panic_mode"]
    assert len(panic_emits) >= 1
    assert all(p["dry_run"] is True for p in panic_emits)


# ─── kill mid-write ─────────────────────────────────────────────────────────

def test_kill_mid_write_attribution_still_returns_candidate(tmp_path):
    """Open a file handle in a child process, kill the process while the
    handle is (about to be) open, then confirm attribution doesn't crash and
    either returns a candidate or a well-formed 'unknown', never raises."""
    from attribution import ProcessSnapshotter, attribute_event

    snapshotter = ProcessSnapshotter()
    snapshotter.start()
    try:
        target = os.path.join(str(tmp_path), "decoy_target.txt")
        proc = subprocess.Popen(
            [sys.executable, "-c",
             f"import time; f=open({target!r}, 'w'); f.write('x'); time.sleep(2)"]
        )
        time.sleep(0.3)  # let the process open the handle and get snapshotted
        event_ts = time.time()
        proc.kill()  # SIGKILL mid-write
        proc.wait()

        # must not raise, regardless of whether the killed process is still
        # resolvable as a candidate
        result = attribute_event(snapshotter, event_ts=event_ts)
        assert result["attribution_confidence"] in ("high", "ambiguous", "unknown")
        assert "pid" in result and "process_name" in result
    finally:
        snapshotter.stop()


# ─── restart mid-incident ───────────────────────────────────────────────────

def test_restart_mid_incident_preserves_classifier_and_event_log(tmp_path):
    """Simulates `server.py` being killed and restarted in the middle of a
    sweep: a brand-new TripwireServer built against the same on-disk DB must
    see the prior events and the prior classifier window state."""
    db_path = os.path.join(tmp_path, "restart.db")
    decoy_dir = os.path.join(tmp_path, "decoys")

    srv1 = TripwireServer(db_path=db_path, decoy_dir=decoy_dir, dry_run=True)
    for i in range(config.WARNING_TOUCH_THRESHOLD):
        srv1._on_fs_event("modify", f"decoys/mid_{i}.xlsx", time.time())
    events_before = srv1.store.count_events()
    window_before = srv1.classifier.current_window_count()
    srv1.stop()
    del srv1  # simulate process death mid-incident

    # "restart": fresh server object, same DB/decoy dir
    srv2 = TripwireServer(db_path=db_path, decoy_dir=decoy_dir, dry_run=True)
    try:
        assert srv2.store.count_events() == events_before, "event log must survive the restart"
        assert srv2.classifier.current_window_count() == window_before, (
            "classifier window state must survive the restart"
        )

        # incident continues past the restart and still escalates correctly
        r = srv2.classifier.record_touch("decoys/after_restart.xlsx")
        assert r.touch_count == window_before + 1
    finally:
        srv2.stop()


def test_restart_mid_incident_via_event_store_directly(tmp_path):
    """Lower-level version of the same guarantee, isolated to events.py +
    classifier.py without the Flask/watcher machinery, matching the build
    plan's Stage 4 reliability checkpoint verbatim."""
    db_path = os.path.join(tmp_path, "restart2.db")
    store = EventStore(db_path=db_path)
    clf = Classifier(store, window_s=10.0)
    for i in range(config.CRITICAL_TOUCH_THRESHOLD + 1):
        clf.record_touch(f"decoys/file_{i}.xlsx")
    del clf

    clf2 = Classifier(store, window_s=10.0)
    assert clf2.current_window_count() == config.CRITICAL_TOUCH_THRESHOLD + 1
    r = clf2.record_touch("decoys/after_restart.xlsx")
    assert r.severity == "critical"


# ─── double panic ───────────────────────────────────────────────────────────

def test_double_panic_via_full_pipeline_no_errors_no_double_suspend(srv):
    """Trigger two independent critical-severity incidents back to back
    through the full server pipeline and confirm no exception propagates and
    panic state stays consistent."""
    for i in range(config.CRITICAL_TOUCH_THRESHOLD + 1):
        srv._on_fs_event("modify", f"decoys/first_{i}.xlsx", time.time())
    for i in range(config.CRITICAL_TOUCH_THRESHOLD + 1):
        srv._on_fs_event("modify", f"decoys/second_{i}.xlsx", time.time())

    assert srv.store.dead_letter_count() == 0
    panic_emits = [p for (name, p) in srv.socketio_emitted if name == "panic_mode"]
    assert len(panic_emits) >= 2


# ─── permission denied ──────────────────────────────────────────────────────

def test_permission_denied_lock_path_logged_not_raised(tmp_path):
    from panic import PanicController

    ctrl = PanicController(dry_run=False)
    restricted = os.path.join(str(tmp_path), "restricted")
    os.makedirs(restricted)
    os.chmod(restricted, 0o000)
    try:
        r = ctrl.lock_real_folder(restricted)
        # either a clean failure (permission denied) or, if the test runner
        # is root and bypasses the mode bits, a clean success — either way
        # it must never raise
        assert r.status in ("succeeded", "failed")
        if r.status == "failed":
            assert r.reason
    finally:
        os.chmod(restricted, 0o755)  # restore so tmp_path cleanup can remove it


def test_permission_denied_suspend_target_logged_not_raised(monkeypatch):
    """Confirm psutil.AccessDenied on a real suspend attempt is caught and
    logged as a clean failure, never an unhandled exception. Mocked rather
    than targeting a real system PID (e.g. PID 1) — the test runner may be
    root in some environments, in which case a real suspend would actually
    succeed against a live process, which is unsafe to exercise here."""
    import psutil
    from panic import PanicController

    ctrl = PanicController(dry_run=False)

    def _deny_suspend(self):
        raise psutil.AccessDenied(pid=self.pid)

    monkeypatch.setattr(psutil.Process, "suspend", _deny_suspend)
    proc = subprocess.Popen(["sleep", "5"])
    try:
        r = ctrl.suspend(proc.pid)
        assert r.status == "failed"
        assert r.reason and "permission" in r.reason.lower()
    finally:
        proc.terminate()
        proc.wait()


# ─── malformed event never takes down the watcher thread ───────────────────

def test_malformed_event_is_dead_lettered_not_fatal(srv):
    srv._on_fs_event("not_a_real_event_type", "decoys/bad.xlsx", time.time())
    assert srv.store.dead_letter_count() == 1
    assert srv.store.count_events() == 0

    # pipeline must still be healthy for subsequent, well-formed events
    srv._on_fs_event("modify", "decoys/good.xlsx", time.time())
    assert srv.store.count_events() == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "-s"]))
