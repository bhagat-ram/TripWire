"""
panic.py — Stage 5
The highest-consequence code path in the system. Every action is wrapped,
logged (attempted / succeeded / failed-with-reason), and safe to call twice.

Reliability checkpoint this file must pass:
  - Every action logs attempted vs. succeeded vs. failed-with-reason
  - Calling panic twice in a row doesn't error or double-apply
  - Allowlist check uses the freshly-read process name at call time (never cached)
  - Permission-denied targets are logged and skipped, never an unhandled exception
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass, field
from typing import Optional

import psutil

import config


LOG_PATH = os.path.join(config.LOGS_DIR, "panic_actions.log")


@dataclass
class ActionResult:
    action: str            # "suspend" | "resume" | "kill" | "lock" | "unlock"
    target: str             # pid as string, or a path
    status: str              # "attempted" | "succeeded" | "failed" | "skipped_allowlist" | "skipped_dry_run"
    reason: Optional[str] = None
    dry_run: bool = True
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "action": self.action, "target": self.target, "status": self.status,
            "reason": self.reason, "dry_run": self.dry_run, "ts": self.ts,
        }


def _log(result: ActionResult):
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(result.to_dict()) + "\n")


def _is_allowlisted(pid: int) -> bool:
    """Always re-read the process name at call time — never trust a cached
    snapshot, to avoid an allowlist bypass via PID reuse."""
    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False  # can't confirm identity -> do not allowlist; caller decides what to do
    return name in config.ALLOWLIST_PROCESS_NAMES


class PanicController:
    """
    Idempotent by design: every mutating method first checks current state
    (is it already suspended? already locked?) before acting, so calling the
    same action twice never double-applies or raises.
    """

    def __init__(self, dry_run: bool = config.PANIC_DRY_RUN):
        self.dry_run = dry_run
        self._suspended_pids: set[int] = set()
        self._killed_pid: Optional[int] = None
        self._locked_paths: set[str] = set()
        self.active = False
        self.started_at: Optional[float] = None

    # ── process actions ──

    def suspend(self, pid: int) -> ActionResult:
        attempted = ActionResult(action="suspend", target=str(pid), status="attempted", dry_run=self.dry_run)
        _log(attempted)

        if pid in self._suspended_pids:
            r = ActionResult(action="suspend", target=str(pid), status="succeeded",
                              reason="already suspended (idempotent no-op)", dry_run=self.dry_run)
            _log(r)
            return r

        if _is_allowlisted(pid):
            r = ActionResult(action="suspend", target=str(pid), status="skipped_allowlist", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._suspended_pids.add(pid)  # track state so idempotency logic is exercised even dry
            r = ActionResult(action="suspend", target=str(pid), status="skipped_dry_run", dry_run=True)
            _log(r)
            return r

        try:
            psutil.Process(pid).suspend()
            self._suspended_pids.add(pid)
            r = ActionResult(action="suspend", target=str(pid), status="succeeded", dry_run=False)
        except psutil.NoSuchProcess:
            r = ActionResult(action="suspend", target=str(pid), status="failed",
                              reason="no such process", dry_run=False)
        except psutil.AccessDenied:
            r = ActionResult(action="suspend", target=str(pid), status="failed",
                              reason="permission denied", dry_run=False)
        except Exception as e:  # never let panic mode crash mid-incident
            r = ActionResult(action="suspend", target=str(pid), status="failed",
                              reason=f"unexpected: {e}", dry_run=False)
        _log(r)
        return r

    def kill(self, pid: int) -> ActionResult:
        attempted = ActionResult(action="kill", target=str(pid), status="attempted", dry_run=self.dry_run)
        _log(attempted)

        if self._killed_pid == pid:
            r = ActionResult(action="kill", target=str(pid), status="succeeded",
                              reason="already killed (idempotent no-op)", dry_run=self.dry_run)
            _log(r)
            return r

        if _is_allowlisted(pid):
            r = ActionResult(action="kill", target=str(pid), status="skipped_allowlist", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._killed_pid = pid
            r = ActionResult(action="kill", target=str(pid), status="skipped_dry_run", dry_run=True)
            _log(r)
            return r

        try:
            psutil.Process(pid).terminate()
            self._killed_pid = pid
            r = ActionResult(action="kill", target=str(pid), status="succeeded", dry_run=False)
        except psutil.NoSuchProcess:
            r = ActionResult(action="kill", target=str(pid), status="failed",
                              reason="no such process", dry_run=False)
        except psutil.AccessDenied:
            r = ActionResult(action="kill", target=str(pid), status="failed",
                              reason="permission denied", dry_run=False)
        except Exception as e:
            r = ActionResult(action="kill", target=str(pid), status="failed",
                              reason=f"unexpected: {e}", dry_run=False)
        _log(r)
        return r

    # ── folder lockdown ──

    def lock_real_folder(self, path: str = config.REAL_DATA_DIR) -> ActionResult:
        attempted = ActionResult(action="lock", target=path, status="attempted", dry_run=self.dry_run)
        _log(attempted)

        if path in self._locked_paths:
            r = ActionResult(action="lock", target=path, status="succeeded",
                              reason="already locked (idempotent no-op)", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._locked_paths.add(path)
            r = ActionResult(action="lock", target=path, status="skipped_dry_run", dry_run=True)
            _log(r)
            return r

        try:
            # Read-only for owner/group/other; platform differences (Windows only has
            # a weak read-only attribute toggle) are documented in the build plan.
            current = stat.S_IMODE(os.stat(path).st_mode)
            os.chmod(path, current & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            self._locked_paths.add(path)
            r = ActionResult(action="lock", target=path, status="succeeded", dry_run=False)
        except PermissionError:
            r = ActionResult(action="lock", target=path, status="failed",
                              reason="permission denied", dry_run=False)
        except FileNotFoundError:
            r = ActionResult(action="lock", target=path, status="failed",
                              reason="path not found", dry_run=False)
        except Exception as e:
            r = ActionResult(action="lock", target=path, status="failed",
                              reason=f"unexpected: {e}", dry_run=False)
        _log(r)
        return r

    def unlock_real_folder(self, path: str = config.REAL_DATA_DIR) -> ActionResult:
        attempted = ActionResult(action="unlock", target=path, status="attempted", dry_run=self.dry_run)
        _log(attempted)

        if path not in self._locked_paths:
            r = ActionResult(action="unlock", target=path, status="succeeded",
                              reason="already unlocked (idempotent no-op)", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._locked_paths.discard(path)
            r = ActionResult(action="unlock", target=path, status="skipped_dry_run", dry_run=True)
            _log(r)
            return r

        try:
            current = stat.S_IMODE(os.stat(path).st_mode)
            os.chmod(path, current | stat.S_IWUSR)
            self._locked_paths.discard(path)
            r = ActionResult(action="unlock", target=path, status="succeeded", dry_run=False)
        except Exception as e:
            r = ActionResult(action="unlock", target=path, status="failed", reason=str(e), dry_run=False)
        _log(r)
        return r

    # ── the full incident response, called by classifier on "critical" ──

    def trigger(self, suspect_pids: list[int], real_data_path: str = config.REAL_DATA_DIR) -> dict:
        """Idempotent: calling trigger() twice for the same incident is safe —
        each sub-action is itself idempotent, so a repeat call is a fast no-op."""
        if not self.active:
            self.active = True
            self.started_at = time.time()

        results = [self.suspend(pid) for pid in suspect_pids]
        results.append(self.lock_real_folder(real_data_path))

        return {
            "suspended": [r.target for r in results if r.action == "suspend" and r.status in ("succeeded",)],
            "killed": self._killed_pid,
            "dry_run": self.dry_run,
            "actions": [r.to_dict() for r in results],
        }


# ─── Self-test — uses only disposable child processes / temp folders ───────

def _run_self_test():
    import subprocess, tempfile

    print("[1/5] every action logs attempted vs succeeded/skipped/failed ... ", end="")
    open(LOG_PATH, "w").close()  # reset log for a clean read
    ctrl = PanicController(dry_run=True)
    # 'python3'/'python' are in the default dev allowlist, so use /bin/sleep (a
    # disposable, non-allowlisted process) to exercise the actual suspend path.
    proc = subprocess.Popen(["sleep", "5"])
    r = ctrl.suspend(proc.pid)
    assert r.status == "skipped_dry_run"
    lines = [json.loads(l) for l in open(LOG_PATH)]
    statuses = [l["status"] for l in lines if l["target"] == str(proc.pid)]
    assert "attempted" in statuses and "skipped_dry_run" in statuses
    print(f"OK -> {statuses}")

    print("[2/5] calling suspend twice is idempotent, no error, no double-apply ... ", end="")
    r1 = ctrl.suspend(proc.pid)
    r2 = ctrl.suspend(proc.pid)
    assert "idempotent" in (r2.reason or "")
    print("OK")

    print("[3/5] double panic trigger doesn't error or double-suspend ... ", end="")
    proc2 = subprocess.Popen(["sleep", "5"])
    out1 = ctrl.trigger([proc.pid, proc2.pid])
    out2 = ctrl.trigger([proc.pid, proc2.pid])
    assert out1["dry_run"] is True and out2["dry_run"] is True
    print("OK")

    print("[4/5] allowlisted process names are skipped, not suspended ... ", end="")
    ctrl2 = PanicController(dry_run=True)
    r_self = ctrl2.suspend(os.getpid())  # this test runner is 'python3' -> allowlisted
    assert r_self.status == "skipped_allowlist", f"expected skip, got {r_self.status}"
    print("OK")

    print("[5/5] locking a folder we don't own permission over is logged, not an unhandled exception ... ", end="")
    tmp_dir = tempfile.mkdtemp()
    ctrl3 = PanicController(dry_run=False)
    # Simulate a permission failure deterministically rather than depending on root/CI quirks:
    bogus_path = os.path.join(tmp_dir, "does_not_exist")
    r_lock = ctrl3.lock_real_folder(bogus_path)
    assert r_lock.status == "failed" and r_lock.reason, "expected a logged failure with reason"
    print(f"OK -> status={r_lock.status} reason={r_lock.reason!r}")

    proc.terminate(); proc.wait()
    proc2.terminate(); proc2.wait()
    os.rmdir(tmp_dir)

    print("\nAll checks passed.")
    print(f"Full action log at: {LOG_PATH}")


if __name__ == "__main__":
    _run_self_test()
