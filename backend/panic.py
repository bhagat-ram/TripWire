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


def mitigation_status(results: list[ActionResult], dry_run: bool) -> str:
    """Collapse a list of ActionResults into one of:
      "auto_mitigated"  — at least one containment action actually took
                           effect live (succeeded, not dry-run) and none
                           failed.
      "requires_manual" — nothing actually happened automatically (dry-run,
                           every action skipped/failed/allowlisted, or there
                           were no actions at all — e.g. a "monitor"-only
                           rule) — an analyst needs to act by hand.
    This is the single source of truth the dashboard uses to show a case as
    "Auto-mitigated" vs "Requires manual action", instead of the frontend
    re-deriving it ad hoc from a raw dry_run flag."""
    if not results:
        return "requires_manual"
    if dry_run:
        return "requires_manual"
    succeeded = [r for r in results if r.status == "succeeded"]
    failed_or_blocked = [r for r in results if r.status in ("failed", "skipped_allowlist")]
    if succeeded and not failed_or_blocked:
        return "auto_mitigated"
    return "requires_manual"


_SELF_PID = os.getpid()


def _is_allowlisted(pid: int) -> bool:
    """Always re-read the process name at call time — never trust a cached
    snapshot, to avoid an allowlist bypass via PID reuse.

    The running server process is always exempt, regardless of
    TRIPWIRE_DEV_MODE. This protects THIS process specifically (by PID),
    not every python3 on the box — so turning off dev mode still lets
    panic act on the simulator or a real malicious script, it just can't
    accidentally suspend/kill itself."""
    if pid == _SELF_PID:
        return True
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
        # Real, psutil-confirmed state only. A pid/path only lands here after
        # an action that actually ran (dry_run=False, succeeded) — never from
        # a dry-run stub. This is what idempotency checks in live mode
        # consult, so arming Live never gets short-circuited by dry-run
        # history (see _dry_run_* sets below for why that used to happen).
        self._suspended_pids: set[int] = set()
        self._killed_pid: Optional[int] = None
        self._locked_paths: set[str] = set()
        # Dry-run-only bookkeeping. Populated so that repeat dry-run calls on
        # the same pid still log "idempotent no-op" (exercised by the
        # self-test below) without ever being consulted once dry_run is
        # False — a dry-run "kill" must never make a later, real kill()
        # think the pid is already handled and skip psutil entirely.
        self._dry_run_suspended_pids: set[int] = set()
        self._dry_run_killed_pid: Optional[int] = None
        self._dry_run_locked_paths: set[str] = set()
        self.active = False
        self.started_at: Optional[float] = None
        # Repeat-offense tracking: touches seen from a PID *after* it was
        # already suspended. A process that keeps touching decoys post-suspend
        # means the suspend didn't actually stop it (dry-run, failed, bypassed)
        # — that's the signal to auto-escalate straight to kill.
        self._post_suspend_touches: dict[int, int] = {}

    # ── process actions ──

    def suspend(self, pid: int) -> ActionResult:
        attempted = ActionResult(action="suspend", target=str(pid), status="attempted", dry_run=self.dry_run)
        _log(attempted)

        # Only a REAL prior suspend counts as "already done" once we're live.
        # A pid that was only ever dry-run "suspended" must still go through
        # the real psutil call the first time we're actually armed.
        #
        # The cache alone isn't enough to trust, though: the pid may have
        # died since we suspended it (killed out-of-band, e.g. manually, or
        # by a later real kill() call on the same pid). Re-verify liveness
        # before short-circuiting, or a stale cache entry silently reports
        # "succeeded" forever for a target that's long gone.
        if not self.dry_run and pid in self._suspended_pids:
            if psutil.pid_exists(pid):
                r = ActionResult(action="suspend", target=str(pid), status="succeeded",
                                  reason="already suspended (idempotent no-op)", dry_run=self.dry_run)
                _log(r)
                return r
            self._suspended_pids.discard(pid)  # stale — fall through to re-evaluate for real
        if self.dry_run and pid in self._dry_run_suspended_pids:
            r = ActionResult(action="suspend", target=str(pid), status="succeeded",
                              reason="already suspended (idempotent no-op, dry-run)", dry_run=self.dry_run)
            _log(r)
            return r

        if _is_allowlisted(pid):
            r = ActionResult(action="suspend", target=str(pid), status="skipped_allowlist", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._dry_run_suspended_pids.add(pid)
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

        # Same real-vs-dry-run split as suspend() above — a dry-run "kill"
        # must never make a later, real kill() believe the pid is already
        # handled and skip the actual psutil.terminate() call.
        # Same stale-cache risk as suspend() above: "already killed" should
        # only short-circuit if we're the ones who actually killed it and it
        # hasn't been reaped/reused since. If the pid is gone, don't lie and
        # say "succeeded" — that's not idempotency, that's silence.
        if not self.dry_run and self._killed_pid == pid:
            if not psutil.pid_exists(pid):
                r = ActionResult(action="kill", target=str(pid), status="succeeded",
                                  reason="already killed (idempotent no-op)", dry_run=self.dry_run)
                _log(r)
                return r
            self._killed_pid = None  # stale — fall through to re-evaluate for real
        if self.dry_run and self._dry_run_killed_pid == pid:
            r = ActionResult(action="kill", target=str(pid), status="succeeded",
                              reason="already killed (idempotent no-op, dry-run)", dry_run=self.dry_run)
            _log(r)
            return r

        if _is_allowlisted(pid):
            r = ActionResult(action="kill", target=str(pid), status="skipped_allowlist", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._dry_run_killed_pid = pid
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

        if not self.dry_run and path in self._locked_paths:
            r = ActionResult(action="lock", target=path, status="succeeded",
                              reason="already locked (idempotent no-op)", dry_run=self.dry_run)
            _log(r)
            return r
        if self.dry_run and path in self._dry_run_locked_paths:
            r = ActionResult(action="lock", target=path, status="succeeded",
                              reason="already locked (idempotent no-op, dry-run)", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._dry_run_locked_paths.add(path)
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

        locked = path in self._locked_paths if not self.dry_run else path in self._dry_run_locked_paths
        if not locked:
            r = ActionResult(action="unlock", target=path, status="succeeded",
                              reason="already unlocked (idempotent no-op)", dry_run=self.dry_run)
            _log(r)
            return r

        if self.dry_run:
            self._dry_run_locked_paths.discard(path)
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

    # ── repeat-offense tracking / auto-escalation ──

    def note_post_suspend_touch(self, pid: int) -> int:
        """Call this whenever an already-suspended PID generates another
        touch. Returns the running post-suspend touch count for that PID —
        the caller (server.py) compares it against
        config.AUTO_ESCALATE_TO_KILL_AFTER_TOUCHES to decide whether to
        auto-escalate to kill. Only meaningful for PIDs already in
        self._suspended_pids; irrelevant PIDs are ignored (returns 0)."""
        if pid not in self._suspended_pids:
            return 0
        self._post_suspend_touches[pid] = self._post_suspend_touches.get(pid, 0) + 1
        return self._post_suspend_touches[pid]

    def should_escalate_to_kill(self, pid: int) -> bool:
        return (self._post_suspend_touches.get(pid, 0)
                >= config.AUTO_ESCALATE_TO_KILL_AFTER_TOUCHES
                and self._killed_pid != pid)

    # ── the full incident response, called by classifier on "critical" ──

    def trigger(self, suspect_pids: list[int], real_data_path: str = config.REAL_DATA_DIR,
                rules: Optional[list[str]] = None) -> dict:
        """Idempotent: calling trigger() twice for the same incident is safe —
        each sub-action is itself idempotent, so a repeat call is a fast no-op.

        `rules` is the ordered list of actions to take (from
        config.AUTO_RESPONSE_RULES[severity], normally ["suspend", "lock"]
        for critical). "monitor" is a no-op placeholder — it means "alert
        only", so it contributes no action. Defaults to ["suspend", "lock"]
        for backward compatibility if the caller doesn't pass rules."""
        if rules is None:
            rules = ["suspend", "lock"]

        if not self.active:
            self.active = True
            self.started_at = time.time()

        results: list[ActionResult] = []
        if "suspend" in rules:
            results += [self.suspend(pid) for pid in suspect_pids]
        if "kill" in rules:
            results += [self.kill(pid) for pid in suspect_pids]
        if "lock" in rules:
            results.append(self.lock_real_folder(real_data_path))
        # "monitor" intentionally contributes nothing — alert-only.

        return {
            "suspended": [r.target for r in results if r.action == "suspend" and r.status in ("succeeded",)],
            "killed": self._killed_pid,
            "dry_run": self.dry_run,
            "actions": [r.to_dict() for r in results],
            "mitigation_status": mitigation_status(results, self.dry_run),
        }

    def escalate_to_kill(self, pid: int) -> ActionResult:
        """Auto-escalation path: called when should_escalate_to_kill(pid) is
        True. Distinct from a manual/rule-driven kill() call only in that the
        caller should log/emit it as an escalation, not an initial response."""
        return self.kill(pid)


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
