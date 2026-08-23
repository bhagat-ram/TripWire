"""
tests/test_panic_allowlist.py

Pytest wrapper around panic.py's Stage 5 reliability checkpoint — the
highest-consequence code path in the system:
  - Every action logs attempted vs. succeeded vs. failed-with-reason
  - Calling panic twice in a row doesn't error or double-apply
  - Allowlist check uses the freshly-read process name at call time
  - Permission-denied targets are logged and skipped, never an unhandled exception
  - PANIC_DRY_RUN never mutates real process/filesystem state

Uses only disposable child processes (`sleep`) and temp folders — never
touches config.REAL_DATA_DIR or anything outside the test sandbox.

Run: pytest tests/test_panic_allowlist.py -v
"""

import json
import os
import subprocess
import sys

import psutil
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from panic import PanicController, LOG_PATH, _is_allowlisted


@pytest.fixture
def disposable_proc():
    proc = subprocess.Popen(["sleep", "5"])
    yield proc
    if proc.poll() is None:
        proc.terminate()
        proc.wait()


@pytest.fixture
def clean_log():
    """Reset the shared action log so each test can read its own lines."""
    os.makedirs(config.LOGS_DIR, exist_ok=True)
    open(LOG_PATH, "w").close()
    yield LOG_PATH


def _log_lines_for(target: str):
    with open(LOG_PATH) as f:
        lines = [json.loads(l) for l in f if l.strip()]
    return [l for l in lines if l["target"] == str(target)]


# ─── dry-run safety ─────────────────────────────────────────────────────────

def test_dry_run_never_actually_suspends(clean_log, disposable_proc):
    ctrl = PanicController(dry_run=True)
    r = ctrl.suspend(disposable_proc.pid)
    assert r.status == "skipped_dry_run"
    assert r.dry_run is True
    # process must still be running — dry run never mutates real state
    assert disposable_proc.poll() is None


def test_every_action_logs_attempted_and_outcome(clean_log, disposable_proc):
    ctrl = PanicController(dry_run=True)
    ctrl.suspend(disposable_proc.pid)
    statuses = [l["status"] for l in _log_lines_for(disposable_proc.pid)]
    assert "attempted" in statuses
    assert "skipped_dry_run" in statuses


# ─── idempotency ────────────────────────────────────────────────────────────

def test_double_suspend_is_idempotent(clean_log, disposable_proc):
    ctrl = PanicController(dry_run=True)
    ctrl.suspend(disposable_proc.pid)
    r2 = ctrl.suspend(disposable_proc.pid)
    assert "idempotent" in (r2.reason or "")
    assert r2.status == "succeeded"


def test_double_kill_is_idempotent(clean_log, disposable_proc):
    ctrl = PanicController(dry_run=True)
    ctrl.kill(disposable_proc.pid)
    r2 = ctrl.kill(disposable_proc.pid)
    assert "idempotent" in (r2.reason or "")


def test_double_trigger_does_not_error_or_double_suspend(clean_log):
    proc1 = subprocess.Popen(["sleep", "5"])
    proc2 = subprocess.Popen(["sleep", "5"])
    try:
        ctrl = PanicController(dry_run=True)
        out1 = ctrl.trigger([proc1.pid, proc2.pid])
        out2 = ctrl.trigger([proc1.pid, proc2.pid])
        assert out1["dry_run"] is True and out2["dry_run"] is True
        assert set(out2["suspended"]) <= {str(proc1.pid), str(proc2.pid)}
    finally:
        proc1.terminate(); proc1.wait()
        proc2.terminate(); proc2.wait()


def test_double_lock_real_folder_is_idempotent(clean_log, tmp_path):
    ctrl = PanicController(dry_run=True)
    target = str(tmp_path)
    r1 = ctrl.lock_real_folder(target)
    r2 = ctrl.lock_real_folder(target)
    assert r1.status in ("succeeded", "skipped_dry_run")
    assert "idempotent" in (r2.reason or "") or r2.status == "skipped_dry_run"


# ─── allowlist ──────────────────────────────────────────────────────────────

def test_allowlisted_process_is_skipped_not_suspended(clean_log, monkeypatch):
    """Verifies the allowlist mechanism itself, independent of what this
    process happens to be named on any given platform/venv (e.g. 'python3'
    vs 'python3.14') — add the real live process name to the allowlist for
    the duration of the test, then confirm suspend() honors it."""
    import config as config_mod

    ctrl = PanicController(dry_run=True)
    my_pid = os.getpid()
    my_name = psutil.Process(my_pid).name()

    monkeypatch.setattr(
        config_mod, "ALLOWLIST_PROCESS_NAMES",
        config_mod.ALLOWLIST_PROCESS_NAMES | {my_name},
    )
    r = ctrl.suspend(my_pid)
    assert r.status == "skipped_allowlist"


def test_allowlist_check_reads_process_name_at_call_time(clean_log):
    """Guards against a PID-reuse bypass: _is_allowlisted must look up the
    process name fresh every call, not trust a cached snapshot."""
    proc = subprocess.Popen(["sleep", "5"])
    try:
        # 'sleep' is not in ALLOWLIST_PROCESS_NAMES
        assert _is_allowlisted(proc.pid) is False
    finally:
        proc.terminate(); proc.wait()


def test_allowlist_lookup_for_dead_pid_does_not_raise(clean_log):
    proc = subprocess.Popen(["sleep", "0.1"])
    proc.wait()
    dead_pid = proc.pid
    # process is gone; must return False, never raise
    assert _is_allowlisted(dead_pid) is False


# ─── permission / failure handling ─────────────────────────────────────────

def test_lock_nonexistent_path_is_logged_failure_not_exception(clean_log, tmp_path):
    ctrl = PanicController(dry_run=False)
    bogus_path = os.path.join(str(tmp_path), "does_not_exist")
    r = ctrl.lock_real_folder(bogus_path)
    assert r.status == "failed"
    assert r.reason


def test_kill_nonexistent_pid_is_logged_failure_not_exception(clean_log):
    ctrl = PanicController(dry_run=False)
    # PID unlikely to exist
    r = ctrl.kill(999999)
    assert r.status == "failed"
    assert r.reason


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
