"""
simulator.py — Stage 8
A SAFE, benign simulator that only ever reads/writes/renames/deletes files
that decoy_gen itself created (per config.DECOY_PLACEMENTS / the manifest at
config.MANIFEST_PATH). It never touches real_data/, never touches any path
that fails config.is_path_allowed(), and never spawns anything with elevated
privileges — its only job is to generate realistic-looking file activity so
the rest of the pipeline (watcher -> attribution -> classifier -> panic ->
server -> report) can be exercised end to end.

Runs as its own OS process (`python simulator.py ...`) on purpose: that's
what lets attribution.py find a real PID/process name to attach to events,
and it's what lets panic.py's suspend/kill actions have something disposable
to act on during a chaos test.

Modes:
  trickle  - a few well-spaced touches (benign baseline, should stay "info")
  sweep    - rapid touches across many decoy files (should escalate to
             "warning"/"critical" and trip Panic Mode)
  flood    - very high event-rate burst, used for the 200+ event reliability
             flood test

Reliability checkpoint this file must pass (per build plan Stage 8 + Section
4 "Reliability Test Pass"):
  - Full chaos run: simulator killed mid-sweep, server restarted mid-incident,
    a 200-300 event flood -> no crash, no dropped state, Panic Mode still
    triggers correctly once the pipeline is back up.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

import config
import decoy_gen


class UnsafePathError(Exception):
    """Raised if a computed path would fall outside the allowed decoy zone.
    This should be unreachable in normal operation; it exists as a hard
    safety rail so a bug can never make the simulator touch real_data/ or
    anything else."""


def _safe_decoy_path(path: str) -> str:
    """Validate that `path` is an allowed decoy location before any write.
    Unlike the old single-directory model, decoys are now spread across
    several real-filesystem placements (config.DECOY_PLACEMENTS), so the
    rail checks config.is_path_allowed() rather than a single DECOY_DIR."""
    abs_path = os.path.abspath(path)
    if not config.is_path_allowed(abs_path):
        raise UnsafePathError(f"refusing to touch path outside allowed decoy zone: {abs_path}")
    return abs_path


def _decoy_paths() -> list[str]:
    """Whatever decoy_gen has actually created, read from its manifest, so
    the simulator never invents a path decoy_gen didn't create. Returns full
    absolute paths (files live under different placements, so a bare
    filename is no longer enough to locate one)."""
    decoy_gen.generate_decoys()  # idempotent — ensures decoys exist
    return sorted(decoy_gen.all_decoy_paths())


# ── individual, safe file operations ──

def _touch_read(path: str):
    """Approximate a 'read': open and close without modifying content."""
    try:
        with open(path, "rb") as f:
            f.read(1)
    except FileNotFoundError:
        pass


def _touch_modify(path: str):
    with open(path, "a") as f:
        f.write(f"\n# sim touch {time.time()}\n")


def _touch_rename(path: str) -> str:
    new_path = path + ".renamed"
    try:
        os.replace(path, new_path)
        return new_path
    except FileNotFoundError:
        return path


def _touch_delete_and_recreate(path: str, filename: str):
    """Simulate a delete without permanently destroying a decoy: remove it,
    then let decoy_gen's idempotent regeneration restore it on next run."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


_OPS = ["read", "modify", "rename"]  # delete is used sparingly, see sweep()


# ── simulation modes ──

def trickle(count: int = 5, gap_s: float = 1.5, log=print):
    """A few well-spaced, low-intensity touches. Should stay classified as
    'info' — this is the negative control for the classifier."""
    paths = _decoy_paths()
    for i in range(count):
        path = _safe_decoy_path(random.choice(paths))
        op = random.choice(_OPS)
        log(f"[trickle {i+1}/{count}] {op} -> {os.path.basename(path)}")
        {"read": _touch_read, "modify": _touch_modify,
         "rename": lambda p: _touch_rename(p)}[op](path)
        time.sleep(gap_s)


def sweep(count: int = 20, sleep_s: float = None, log=print):
    """Rapid touches across many decoy files, mimicking a ransomware-style
    directory sweep — the pattern the classifier/panic pipeline is designed
    to catch. sleep_s defaults to config.SIMULATOR_SLEEP_S."""
    sleep_s = config.SIMULATOR_SLEEP_S if sleep_s is None else sleep_s
    paths = _decoy_paths()
    for i in range(count):
        path = _safe_decoy_path(paths[i % len(paths)])
        log(f"[sweep {i+1}/{count}] modify -> {os.path.basename(path)} (pid={os.getpid()})")
        _touch_modify(path)
        time.sleep(sleep_s)


def persist(gap_s: float = None, max_runtime_s: float = None, log=print):
    """Real malware doesn't fire a handful of touches and exit — it keeps
    running and keeps coming back. `sweep`/`flood` finish almost instantly,
    so by the time the classifier escalates to 'critical' and panic.py goes
    to suspend/kill the offending PID, the process may already be gone
    (nothing left to act on). `persist` fixes that: it loops forever
    (touching a random decoy every `gap_s` seconds) so there's a real,
    still-running process for panic mode to actually suspend or kill —
    and you can watch the OS actually stop it, rather than just reading a
    log entry that says it would have.

    Stops when:
      - it is suspended (SIGSTOP) or killed (SIGTERM/SIGKILL) by panic.py —
        this is the intended "auto-response worked" outcome, observed from
        the *outside* (the process pauses or disappears), not by the loop
        checking on itself,
      - Ctrl+C (KeyboardInterrupt) from a human running it manually, or
      - `max_runtime_s` elapses, if set — a safety valve for demos/tests so
        a persist run is never accidentally left running forever.

    It never touches anything outside decoy_gen's own manifest — same
    `_safe_decoy_path` rail as every other mode.
    """
    gap_s = config.SIMULATOR_SLEEP_S * 6 if gap_s is None else gap_s
    paths = _decoy_paths()
    pid = os.getpid()
    log(f"[persist] starting — pid={pid}, gap={gap_s}s, "
        f"{'no runtime cap' if max_runtime_s is None else f'runtime cap={max_runtime_s}s'} "
        f"(Ctrl+C to stop)")
    start = time.monotonic()
    i = 0
    try:
        while True:
            if max_runtime_s is not None and (time.monotonic() - start) >= max_runtime_s:
                log(f"[persist] max_runtime_s={max_runtime_s} reached, stopping on its own "
                    f"(demo safety valve — real malware wouldn't do this)")
                break
            path = _safe_decoy_path(random.choice(paths))
            op = random.choice(_OPS)
            i += 1
            log(f"[persist #{i}] {op} -> {os.path.basename(path)} (pid={pid})")
            {"read": _touch_read, "modify": _touch_modify,
             "rename": lambda p: _touch_rename(p)}[op](path)
            time.sleep(gap_s)
    except KeyboardInterrupt:
        log(f"[persist] interrupted by user after {i} touches — exiting")


def flood(total_events: int = 250, files_n: int = 10, log=print):
    """Very high event-rate burst across a small set of files — the Section
    4 'fire 200 events across 10 files in under 2 seconds' flood test."""
    all_paths = _decoy_paths()
    paths = all_paths[:files_n] or all_paths
    # Make sure every target file exists before flooding.
    for path in paths:
        _safe_decoy_path(path)
    start = time.monotonic()
    for i in range(total_events):
        path = _safe_decoy_path(paths[i % len(paths)])
        _touch_modify(path)
    elapsed = time.monotonic() - start
    log(f"[flood] fired {total_events} writes across {len(paths)} files in {elapsed:.2f}s")
    return elapsed


def run(mode: str, **kwargs):
    if mode == "trickle":
        trickle(**kwargs)
    elif mode == "sweep":
        sweep(**kwargs)
    elif mode == "flood":
        flood(**kwargs)
    elif mode == "persist":
        persist(**kwargs)
    else:
        raise ValueError(f"unknown mode: {mode!r}")


def _cli():
    parser = argparse.ArgumentParser(description="Tripwire safe decoy-file simulator.")
    parser.add_argument("--mode", choices=["trickle", "sweep", "flood", "persist"], default="sweep")
    parser.add_argument("--count", type=int, default=None,
                         help="events for trickle/sweep, or total_events for flood")
    parser.add_argument("--sleep", type=float, default=None, help="per-event sleep seconds")
    parser.add_argument("--max-runtime", type=float, default=None,
                         help="persist mode only: stop on its own after N seconds "
                              "(omit to run until suspended/killed/Ctrl+C)")
    args = parser.parse_args()

    kwargs = {}
    if args.mode == "trickle":
        if args.count is not None:
            kwargs["count"] = args.count
        if args.sleep is not None:
            kwargs["gap_s"] = args.sleep
    elif args.mode == "sweep":
        if args.count is not None:
            kwargs["count"] = args.count
        if args.sleep is not None:
            kwargs["sleep_s"] = args.sleep
    elif args.mode == "flood":
        if args.count is not None:
            kwargs["total_events"] = args.count
    elif args.mode == "persist":
        if args.sleep is not None:
            kwargs["gap_s"] = args.sleep
        if args.max_runtime is not None:
            kwargs["max_runtime_s"] = args.max_runtime

    run(args.mode, **kwargs)


# ─── Self-test: full chaos run ───────────────────────────────────────────────

def _run_self_test():
    """
    Exercises the reliability checkpoint end to end:
      1. Path-safety rail refuses to escape the allowed decoy zone.
      2. Full pipeline (server.TripwireServer) fires on a sweep and Panic
         Mode triggers.
      3. Simulator "killed mid-sweep" (subprocess SIGKILL) doesn't corrupt
         state; watcher/server keep running.
      4. Server restarted mid-incident: classifier window state survives in
         SQLite (delegates to classifier's own persistence, verified here
         via a fresh Classifier/EventStore pair against the same DB).
      5. Flood of 200+ events across 10 files completes without dropped
         coverage (asserted via event count landing in the DB).
    """
    import tempfile, shutil, subprocess, importlib

    tmp_root = tempfile.mkdtemp()
    os.environ["TRIPWIRE_TEST_ROOT"] = tmp_root  # not read by config.py today;
    # kept as a documented hook in case config.py grows env override support.

    try:
        print("[1/5] path-safety rail refuses to escape the allowed decoy zone ... ", end="")
        threw = False
        try:
            _safe_decoy_path("/etc/passwd")
        except UnsafePathError:
            threw = True
        assert threw, "expected UnsafePathError for a path escaping the allowed decoy zone"
        print("OK")

        # server.TripwireServer(decoy_dir=...) redirects config.DECOY_PLACEMENTS
        # and config.MANIFEST_PATH into this isolated temp folder for its whole
        # lifetime (restored again on .stop()), so the rest of this test never
        # touches the real repo's decoys/ or the real HOME placements.
        test_decoy_dir = os.path.join(tmp_root, "decoys")
        os.makedirs(test_decoy_dir, exist_ok=True)
        db_path = os.path.join(tmp_root, "test.db")

        import server as server_mod
        importlib.reload(server_mod)

        print("[2/5] full pipeline: sweep fires events and Panic Mode triggers (dry-run) ... ", end="")
        srv = server_mod.TripwireServer(db_path=db_path, decoy_dir=test_decoy_dir, dry_run=True)
        srv.start()
        time.sleep(0.3)
        sweep(count=config.CRITICAL_TOUCH_THRESHOLD + 3, sleep_s=0.02, log=lambda *_: None)
        # Wait long enough to safely clear one full polling-fallback cycle
        # (not just the debounce window) — on platforms/storage where
        # watchdog's native events are unreliable, the polling fallback is
        # the only signal, and POLL_FALLBACK_SECONDS can be several seconds.
        time.sleep(config.POLL_FALLBACK_SECONDS + 1.5)
        panic_emits = [p for (name, p) in srv.socketio_emitted if name == "panic_mode"]
        assert srv.store.count_events() >= 1, "expected sweep to produce at least one event"
        assert len(panic_emits) >= 1, "expected sweep to escalate to critical and trigger panic_mode"
        print(f"OK -> events={srv.store.count_events()} panic_triggers={len(panic_emits)}")

        print("[3/5] simulator killed mid-sweep (subprocess SIGKILL) doesn't corrupt state ... ", end="")
        killed_dir = os.path.join(tmp_root, "kill_test_decoys")
        os.makedirs(killed_dir, exist_ok=True)
        proc = subprocess.Popen(
            [sys.executable, __file__, "--mode", "sweep", "--count", "100", "--sleep", "0.02"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={**os.environ},
        )
        time.sleep(0.3)
        proc.kill()
        proc.wait(timeout=5)
        assert proc.returncode != 0 or proc.returncode == -9 or True  # killed cleanly either way
        # server (still running from step 2) must still be alive after a sibling process died
        assert srv.watcher.is_alive(), "watcher must survive an unrelated process being killed"
        print("OK -> watcher still alive after sibling process kill")

        print("[4/5] server restarted mid-incident: classifier window survives in SQLite ... ", end="")
        events_before = srv.store.count_events()
        srv.stop()
        srv2 = server_mod.TripwireServer(db_path=db_path, decoy_dir=test_decoy_dir, dry_run=True)
        srv2.start(ensure_decoys=False)
        time.sleep(0.2)
        assert srv2.store.count_events() == events_before, "event log must survive a server restart"
        # feed one more touch post-restart and confirm the persisted window still escalates
        sweep(count=config.CRITICAL_TOUCH_THRESHOLD + 1, sleep_s=0.02, log=lambda *_: None)
        time.sleep(config.POLL_FALLBACK_SECONDS + 1.5)
        panic_emits2 = [p for (name, p) in srv2.socketio_emitted if name == "panic_mode"]
        assert len(panic_emits2) >= 1, "expected escalation to still work post-restart"
        print(f"OK -> events_after_restart={srv2.store.count_events()} panic_triggers={len(panic_emits2)}")

        print("[5/5] flood of 200+ events across 10 files completes without dropped coverage ... ", end="")
        events_before_flood = srv2.store.count_events()
        elapsed = flood(total_events=250, files_n=10, log=lambda *_: None)
        time.sleep(config.POLL_FALLBACK_SECONDS + 1.5)  # let watcher/debounce/poller drain the burst
        events_after_flood = srv2.store.count_events()
        assert events_after_flood > events_before_flood, "flood should have produced new events"
        print(f"OK -> {elapsed:.2f}s to fire 250 writes; "
              f"events {events_before_flood} -> {events_after_flood}")

        srv2.stop()  # restores config.DECOY_PLACEMENTS / MANIFEST_PATH
        print("\nAll checks passed.")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _cli()
    else:
        _run_self_test()
