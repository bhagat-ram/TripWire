"""
server.py — Stage 6
Wires the full pipeline: Watcher → attribution → classifier → store →
WebSocket + REST, with panic on "critical".

WebSocket events emitted (frozen contract — frontend depends on this):
  "tripwire_event"  → enriched event dict (see _enrich below)
  "panic_mode"      → {suspended, killed, dry_run, actions, mitigation_status,
                        event_id, escalation, escalation_reason?}
                       mitigation_status is "auto_mitigated" (a real, non-dry-run
                       action actually succeeded) or "requires_manual" (dry-run,
                       nothing succeeded, or the rule for this severity is
                       monitor-only). escalation=true means this panic_mode was
                       fired by the auto-escalate-to-kill path (a PID kept
                       touching decoys after being suspended), not the initial
                       critical-severity response.
  "response_ack"    → {event_id, action, status, dry_run, ts}
  "health_tick"     → watcher health, emitted every 5 s

REST endpoints:
  GET  /health                 watcher + dead-letter status
  GET  /events[?limit=N]       recent event history
  GET  /manifest               decoy placements + file list
  GET  /audit[?limit=N]        panic_actions.log as JSON
  GET  /report[?limit=N]       generate + download a PDF incident report
  POST /action                 trigger a manual response (suspend/kill/lock)
  POST   /simulate              launch a real simulator.py subprocess (default mode: persist)
  GET    /simulate              list tracked simulator subprocesses + alive state
  DELETE /simulate/<pid>        stop a tracked simulator subprocess
  POST /config/thresholds      update warning/critical thresholds live
  GET  /config/auto-response   current per-severity auto-response rules + escalation threshold
  POST /config/auto-response   update auto-response rules and/or escalation threshold live
  POST /config/dry-run         toggle dry-run (requires {"confirm": true})
  GET    /cases                list persisted case state
  POST   /cases                upsert a case (body: full case dict, needs id + key)
  GET    /cases/<id>           fetch one case
  DELETE /cases/<id>           delete one case
  DELETE /cases                delete every persisted case (full Reset)
  DELETE /events[?before=ts]   delete event history — all, or older than a cutoff (full Reset)
  DELETE /events/<id>          delete a single event row (clear one row from the feed)

Reliability checkpoints:
  - A bad/malformed event dead-letters and continues — never crashes the thread.
  - /health accurately reflects watcher_alive + last_event_ts + dead_letter_count.
  - /config/dry-run refuses to arm without explicit {"confirm": true} body field.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from typing import Optional

from flask import Flask, jsonify, request, send_file

try:
    from flask_socketio import SocketIO
    _HAVE_SOCKETIO = True
except ImportError:
    _HAVE_SOCKETIO = False

    class SocketIO:
        def __init__(self, app, *a, **kw):
            self.app = app
            self.emitted: list[tuple[str, dict]] = []
        def emit(self, name, payload=None, **kw):
            self.emitted.append((name, payload))
        def run(self, app, host="127.0.0.1", port=5000, **kw):
            app.run(host=host, port=port)

import config
from events import Event, EventStore
from attribution import ProcessSnapshotter, attribute_event
from classifier import Classifier
from panic import PanicController, LOG_PATH as PANIC_LOG_PATH, mitigation_status as panic_mitigation_status
import panic as panic_mod
from watcher import Watcher
from report import generate_report
import decoy_gen
import fanotify_watcher


# ─── Helpers ──────────────────────────────────────────────────────────────

def _placement_meta(abs_path: str) -> dict:
    """Return placement label + kind for a given absolute decoy path."""
    parent = os.path.dirname(abs_path)
    for p in config.DECOY_PLACEMENTS:
        if os.path.realpath(p["path"]) == os.path.realpath(parent):
            return {"placement_label": p["label"], "placement_kind": p["kind"], "placement_id": p["id"]}
    return {"placement_label": "unknown", "placement_kind": "unknown", "placement_id": "unknown"}


_RECOMMENDED: dict[str, str] = {
    "info":     "monitor",
    "warning":  "investigate — check process tree and attribution",
    "critical": "suspend suspect process and review immediately",
}


def _enrich(ev: Event, touch_count: int) -> dict:
    """Build the enriched WebSocket payload — superset of ev.to_dict()."""
    d = ev.to_dict()
    d["abs_path"]          = ev.file_path            # already abs from watcher
    d["filename"]          = os.path.basename(ev.file_path)
    d["touch_count"]       = touch_count
    d["recommended_action"] = _RECOMMENDED.get(ev.severity, "monitor")
    d.update(_placement_meta(ev.file_path))
    return d


# ─── Main server class ────────────────────────────────────────────────────

class TripwireServer:
    """Owns every long-lived component and the glue between them.
    Kept as a class so tests can spin up isolated instances."""

    def __init__(self, db_path: str = config.DB_PATH, decoy_dir: Optional[str] = None,
                 dry_run: bool = config.PANIC_DRY_RUN,
                 full_system_monitor: bool = config.FULL_SYSTEM_MONITOR_ENABLED):
        # When a decoy_dir is supplied (tests, simulator self-test), redirect
        # every real-filesystem decoy placement + the manifest into that one
        # isolated folder so we never touch the caller's actual HOME/tmp.
        # Original globals are stashed and restored in stop().
        self._orig_decoy_placements: Optional[list[dict]] = None
        self._orig_manifest_path: Optional[str] = None
        self.decoy_dir = decoy_dir
        if decoy_dir is not None:
            os.makedirs(decoy_dir, exist_ok=True)
            self._orig_decoy_placements = config.DECOY_PLACEMENTS
            self._orig_manifest_path = config.MANIFEST_PATH
            redirected = []
            for p in config.DECOY_PLACEMENTS:
                p2 = dict(p)
                p2["path"] = os.path.join(decoy_dir, p["id"])
                os.makedirs(p2["path"], exist_ok=True)
                redirected.append(p2)
            config.DECOY_PLACEMENTS = redirected
            config.MANIFEST_PATH = os.path.join(decoy_dir, ".manifest.json")

        self.store       = EventStore(db_path=db_path)
        self.classifier  = Classifier(self.store)
        self.snapshotter = ProcessSnapshotter()
        self.panic       = PanicController(dry_run=dry_run)
        self.watcher     = Watcher(callback=self._on_fs_event)

        # Optional, off by default, Linux+root only — see fanotify_watcher.py.
        # Kept as a separate object/stream from self.watcher: it never calls
        # self.classifier or self.panic, only its own in-memory buffer +
        # WebSocket "fs_open".
        self.full_system_monitor_requested = full_system_monitor
        self.fs_monitor: Optional[fanotify_watcher.FanotifyWatcher] = None
        self.fs_monitor_error: Optional[str] = None
        self._fs_audit_buffer: list[dict] = []
        self._fs_audit_lock = threading.Lock()

        self.app      = Flask(__name__)
        self.socketio = (SocketIO(self.app, cors_allowed_origins="*")
                         if _HAVE_SOCKETIO else SocketIO(self.app))

        # The dashboard runs on a different origin (e.g. the Vite dev server
        # on :5173) than this Flask app (:5050 by default). SocketIO already
        # allows cross-origin via cors_allowed_origins above, but that only
        # covers the WebSocket — plain REST calls (fetch() from the browser
        # to /health, /config/thresholds, etc.) are a separate cross-origin
        # request that the browser blocks unless *these* responses also carry
        # CORS headers. Without this, those fetch() calls throw before the
        # frontend ever sees a real response, which surfaces to the user as
        # a misleading "backend unreachable" even though the server is up
        # and the WebSocket is connected fine.
        @self.app.after_request
        def _add_cors_headers(response):
            response.headers["Access-Control-Allow-Origin"] = "*"
            # Must list every method any route actually uses, or the browser's
            # CORS preflight silently blocks it before the request is ever
            # sent. DELETE was missing here — every /events/<id>, /events,
            # /cases/<id>, /cases DELETE call from the dashboard was being
            # blocked at the browser level. Locally the UI still looked like
            # it removed the row (React state updates regardless of whether
            # the network call succeeds), but the backend never actually
            # deleted anything, so a refresh (or any refetch) brought it
            # right back — looking exactly like "clearing" did nothing.
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            return response

        # Unified emit log — works with both real flask-socketio and the shim.
        self.socketio_emitted: list[tuple[str, dict]] = []
        _orig_emit = self.socketio.emit
        def _tracking_emit(name, payload=None, **kw):
            self.socketio_emitted.append((name, payload))
            return _orig_emit(name, payload, **kw)
        self.socketio.emit = _tracking_emit

        self._last_event_ts: Optional[float] = None
        self._state_lock = threading.Lock()

        # Real simulator.py subprocesses launched via POST /simulate (the
        # dashboard's "Simulate detection" button), keyed by pid, so
        # DELETE /simulate/<pid> can stop them and stop() can clean up any
        # still-running ones (mainly persist mode, which otherwise runs
        # forever) instead of leaking demo processes.
        self._sim_procs: dict[int, subprocess.Popen] = {}
        self._sim_lock = threading.Lock()

        # Health ticker — emits "health_tick" every 5 s so the dashboard
        # top bar shows live watcher state without polling /health.
        self._health_stop = threading.Event()
        self._health_thread: Optional[threading.Thread] = None

        self._register_routes()

    # ── full-system audit (fanotify) — deliberately does NOT touch
    # classifier/panic, see fanotify_watcher.py's module docstring ────────

    def _on_full_system_open(self, ev: fanotify_watcher.FileOpenEvent):
        """fanotify reader thread calls this for every file WRITE
        (FAN_CLOSE_WRITE) on the marked mount(s) — not every open(), see
        fanotify_watcher.py's docstring. Must never raise — mirrors
        _on_fs_event's contract. Socket event name ("fs_open") and field
        names are kept as-is for wire compatibility with the frontend."""
        d = {
            "pid": ev.pid,
            "process_name": ev.process_name,
            "exe_path": ev.exe_path,
            "file_path": ev.file_path,
            "ts": ev.ts,
        }
        with self._fs_audit_lock:
            self._fs_audit_buffer.append(d)
            overflow = len(self._fs_audit_buffer) - config.FULL_SYSTEM_MONITOR_BUFFER_SIZE
            if overflow > 0:
                del self._fs_audit_buffer[:overflow]
        self.socketio.emit("fs_open", d)

    # ── pipeline ──────────────────────────────────────────────────────────

    def _on_fs_event(self, event_type: str, file_path: str, ts: float):
        """Watcher debounce thread calls this.  Must NEVER raise."""
        raw = json.dumps({"event_type": event_type, "file_path": file_path, "ts": ts})
        try:
            attrib = attribute_event(self.snapshotter, event_ts=ts)
            attrib.pop("_all_candidates", None)

            result = self.classifier.record_touch(file_path)

            ev = Event(
                event_type=event_type,
                file_path=file_path,
                pid=attrib["pid"],
                process_name=attrib["process_name"],
                attribution_confidence=attrib["attribution_confidence"],
                parent_pid=attrib["parent_pid"],
                parent_name=attrib["parent_name"],
                severity=result.severity,
                mitre_id=result.mitre_id,
                timestamp=ts,
            )
            ev_id = self.store.insert_event(ev)
            ev.id = ev_id

            self.socketio.emit("tripwire_event", _enrich(ev, result.touch_count))

            with self._state_lock:
                self._last_event_ts = ts

            pid = attrib["pid"]

            # Repeat-offense check FIRST, on every touch (any severity): if this
            # PID was already suspended by an earlier critical hit and it's
            # still generating touches, that's live evidence the suspend didn't
            # actually stop it (dry-run / bypass / failed). Auto-escalate to
            # kill once it crosses the threshold — don't wait for another
            # critical classification, which may never come if the window
            # already emptied out.
            if pid is not None:
                post_count = self.panic.note_post_suspend_touch(pid)
                if post_count and self.panic.should_escalate_to_kill(pid):
                    kill_result = self.panic.escalate_to_kill(pid)
                    self.socketio.emit("panic_mode", {
                        "suspended":  [],
                        "killed":     self.panic._killed_pid,
                        "dry_run":    self.panic.dry_run,
                        "actions":    [kill_result.to_dict()],
                        "mitigation_status": panic_mod.mitigation_status([kill_result], self.panic.dry_run),
                        "event_id":   ev_id,
                        "escalation": True,
                        "escalation_reason": (
                            f"pid {pid} touched decoys {post_count}x after being suspended — "
                            f"auto-escalating to kill"
                        ),
                    })

            rules = config.AUTO_RESPONSE_RULES.get(result.severity, [])
            if rules and rules != ["monitor"]:
                suspects = [pid] if pid is not None else []
                panic_result = self.panic.trigger(suspects, rules=rules)
                # panic.trigger already returns "actions" as a list of dicts
                self.socketio.emit("panic_mode", {
                    "suspended":  panic_result["suspended"],
                    "killed":     panic_result["killed"],
                    "dry_run":    panic_result["dry_run"],
                    "actions":    panic_result.get("actions", []),
                    "mitigation_status": panic_result.get("mitigation_status"),
                    "event_id":   ev_id,   # link back to the triggering event
                    "escalation": False,
                })

        except Exception as e:
            self.store.insert_dead_letter(raw, f"{type(e).__name__}: {e}")

    # ── health ticker ─────────────────────────────────────────────────────

    def _health_tick_loop(self):
        while not self._health_stop.wait(5.0):
            with self._state_lock:
                last_ts = self._last_event_ts
            self.socketio.emit("health_tick", {
                "watcher_alive":     self.watcher.is_alive(),
                "last_event_ts":     last_ts,
                "dead_letter_count": self.store.dead_letter_count(),
                "dry_run":           self.panic.dry_run,
                "fs_monitor_alive":  bool(self.fs_monitor and self.fs_monitor.is_alive()),
                "ts":                time.time(),
            })

    # ── REST routes ───────────────────────────────────────────────────────

    def _register_routes(self):

        @self.app.get("/health")
        def health():
            with self._state_lock:
                last_ts = self._last_event_ts
            return jsonify({
                "watcher_alive":         self.watcher.is_alive(),
                "last_event_ts":         last_ts,
                "dead_letter_count":     self.store.dead_letter_count(),
                "dry_run":               self.panic.dry_run,
                "decoy_count":           len(self.watcher.known_paths()),
                "fs_monitor_requested":  self.full_system_monitor_requested,
                "fs_monitor_alive":      bool(self.fs_monitor and self.fs_monitor.is_alive()),
                "fs_monitor_mounts":     self.fs_monitor.marked_mounts() if self.fs_monitor else [],
                "fs_monitor_error":      self.fs_monitor_error,
            })

        @self.app.get("/fs-audit")
        def fs_audit():
            """Recent full-system open() events (fanotify). In-memory only,
            capped at config.FULL_SYSTEM_MONITOR_BUFFER_SIZE — see fanotify_
            watcher.py's docstring for why this doesn't go through the same
            severity pipeline as decoy events."""
            limit = min(int(request.args.get("limit", 200)), config.FULL_SYSTEM_MONITOR_BUFFER_SIZE)
            with self._fs_audit_lock:
                return jsonify(list(reversed(self._fs_audit_buffer))[:limit])

        @self.app.post("/config/full-system-monitor")
        def set_full_system_monitor():
            """Start/stop the fanotify full-system watcher live. Body:
            { "enabled": bool }. Starting it can fail (not root, not Linux,
            kernel too old) — that's returned as a normal 400 with the
            reason, not a 500, since it's an expected/common outcome."""
            body = request.get_json(silent=True) or {}
            enabled = body.get("enabled")
            if not isinstance(enabled, bool):
                return jsonify({"error": "enabled must be a bool"}), 400
            if enabled:
                ok, err = self._start_fs_monitor()
                if not ok:
                    return jsonify({"error": err, "fs_monitor_alive": False}), 400
            else:
                self._stop_fs_monitor()
            return jsonify({
                "fs_monitor_alive":  bool(self.fs_monitor and self.fs_monitor.is_alive()),
                "fs_monitor_mounts": self.fs_monitor.marked_mounts() if self.fs_monitor else [],
                "fs_monitor_error":  self.fs_monitor_error,
            })

        @self.app.get("/events")
        def events():
            limit = min(int(request.args.get("limit", 100)), 500)
            evs = self.store.recent_events(limit=limit)
            return jsonify([_enrich(e, 0) for e in evs])

        @self.app.get("/manifest")
        def manifest():
            """Decoy placement map + file-level status (present / diverged)."""
            mf = decoy_gen.decoy_manifest()
            rows = []
            for key, entry in mf.items():
                p = entry.get("path", "")
                on_disk = os.path.exists(p)
                rows.append({
                    "key":             key,
                    "filename":        os.path.basename(p),
                    "path":            p,
                    "placement_id":    entry.get("placement_id", ""),
                    "placement_label": entry.get("label", ""),
                    "placement_kind":  entry.get("kind", ""),
                    "size":            entry.get("size", 0),
                    "created_at":      entry.get("created_at"),
                    "on_disk":         on_disk,
                })
            placements = config.DECOY_PLACEMENTS
            return jsonify({"placements": placements, "decoys": rows})

        @self.app.get("/audit")
        def audit():
            """Last N lines of panic_actions.log as JSON objects."""
            limit = min(int(request.args.get("limit", 200)), 1000)
            entries = []
            try:
                with open(PANIC_LOG_PATH) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                entries.append({"raw": line})
            except FileNotFoundError:
                pass
            return jsonify(entries[-limit:])

        @self.app.get("/report")
        def report():
            """
            Generate the full PDF incident report (report.py, Stage 7) from
            recent events and return it as a download. This is the "real"
            report — full attribution-confidence stats, MITRE mapping, and
            an always-valid PDF even with zero/degraded events — vs. the
            client-side Markdown summary, which only has whatever the
            WebSocket already pushed to the browser.
            """
            limit = min(int(request.args.get("limit", 500)), 2000)
            fd, tmp_path = tempfile.mkstemp(suffix=".pdf", prefix="tripwire_report_")
            os.close(fd)
            try:
                generate_report(tmp_path, store=self.store, limit=limit)
                return send_file(
                    tmp_path,
                    mimetype="application/pdf",
                    as_attachment=True,
                    download_name=f"tripwire_incident_report_{int(time.time())}.pdf",
                )
            finally:
                # send_file streams the response before this runs on most
                # servers' request lifecycle, but guard with a delayed
                # cleanup rather than deleting a file still being sent.
                threading.Timer(30.0, lambda: os.path.exists(tmp_path) and os.remove(tmp_path)).start()

        @self.app.post("/action")
        def action():
            """
            Manually trigger a response action from the web dashboard.
            Body: { "action": "suspend"|"kill"|"lock", "target": pid_or_path,
                    "event_id": optional_int }
            Manual dashboard actions (suspend/kill) always actually act on
            the target, regardless of the global dry-run/live toggle — a
            click on a specific case is a deliberate, per-target decision.
            Only automatic response (the detection pipeline's trigger())
            still respects dry_run. See panic.py's suspend()/kill()
            force=True.
            """
            body = request.get_json(silent=True) or {}
            act    = body.get("action")
            target = body.get("target")
            ev_id  = body.get("event_id")

            if act not in ("suspend", "kill", "lock"):
                return jsonify({"error": "action must be suspend | kill | lock"}), 400
            # "lock" targets a folder and reasonably defaults to the protected
            # real-data directory; "suspend"/"kill" always need an explicit PID.
            if target is None and act != "lock":
                return jsonify({"error": "target is required"}), 400
            if target is None:
                target = config.REAL_DATA_DIR

            try:
                if act == "suspend":
                    result = self.panic.suspend(int(target), force=True)
                elif act == "kill":
                    result = self.panic.kill(int(target), force=True)
                elif act == "lock":
                    # PanicController exposes lock_real_folder()/unlock_real_folder(),
                    # not lock_file() — this used to 500 on every "lock" action since
                    # nothing hits this route in the test suite. `target` for "lock"
                    # is a folder path (defaults to config.REAL_DATA_DIR if omitted).
                    result = self.panic.lock_real_folder(str(target))
            except Exception as e:
                return jsonify({"error": str(e)}), 500

            ack = {**result.to_dict(), "event_id": ev_id}
            self.socketio.emit("response_ack", ack)
            return jsonify(ack)

        @self.app.post("/config/thresholds")
        def set_thresholds():
            """
            Live-update warning/critical thresholds without restarting.
            Body: { "warning": int, "critical": int }
            """
            body = request.get_json(silent=True) or {}
            w = body.get("warning")
            c = body.get("critical")
            if not (isinstance(w, int) and isinstance(c, int) and 1 <= w < c):
                return jsonify({"error": "warning and critical must be ints with 1 ≤ warning < critical"}), 400
            config.WARNING_TOUCH_THRESHOLD  = w
            config.CRITICAL_TOUCH_THRESHOLD = c
            return jsonify({"warning": w, "critical": c, "ok": True})

        _VALID_ACTIONS = {"monitor", "suspend", "kill", "lock"}
        _VALID_SEVERITIES = {"info", "warning", "critical"}

        @self.app.get("/config/auto-response")
        def get_auto_response():
            """Current per-severity auto-response rules + the auto-escalate-to-kill
            threshold, so the dashboard can render/edit them instead of them only
            being a config.py constant."""
            return jsonify({
                "rules": config.AUTO_RESPONSE_RULES,
                "escalate_to_kill_after_touches": config.AUTO_ESCALATE_TO_KILL_AFTER_TOUCHES,
            })

        @self.app.post("/config/auto-response")
        def set_auto_response():
            """
            Live-update auto-response rules and/or the escalation threshold.
            Body (either or both):
              { "rules": {"info": [...], "warning": [...], "critical": [...]},
                "escalate_to_kill_after_touches": int }
            Each rule list may only contain: monitor, suspend, kill, lock.
            "monitor" means alert-only; combine it with others is redundant
            but harmless (monitor contributes no action either way).
            """
            body = request.get_json(silent=True) or {}
            rules = body.get("rules")
            threshold = body.get("escalate_to_kill_after_touches")

            if rules is not None:
                if not isinstance(rules, dict) or set(rules.keys()) - _VALID_SEVERITIES:
                    return jsonify({"error": f"rules keys must be a subset of {sorted(_VALID_SEVERITIES)}"}), 400
                for sev, actions in rules.items():
                    if not isinstance(actions, list) or any(a not in _VALID_ACTIONS for a in actions):
                        return jsonify({
                            "error": f"rules[{sev!r}] must be a list drawn from {sorted(_VALID_ACTIONS)}"
                        }), 400
                config.AUTO_RESPONSE_RULES = {**config.AUTO_RESPONSE_RULES, **rules}

            if threshold is not None:
                if not (isinstance(threshold, int) and threshold >= 1):
                    return jsonify({"error": "escalate_to_kill_after_touches must be an int ≥ 1"}), 400
                config.AUTO_ESCALATE_TO_KILL_AFTER_TOUCHES = threshold

            return jsonify({
                "rules": config.AUTO_RESPONSE_RULES,
                "escalate_to_kill_after_touches": config.AUTO_ESCALATE_TO_KILL_AFTER_TOUCHES,
                "ok": True,
            })

        _SIMULATE_MODES = {"trickle", "sweep", "flood", "persist"}

        @self.app.post("/simulate")
        def start_simulate():
            """
            The dashboard's "Simulate detection" button. Launches a REAL
            simulator.py subprocess against the real decoy files instead of
            injecting canned demo events into the frontend — so the touches
            actually flow through watcher -> attribution -> classifier ->
            panic exactly like a genuine intrusion would, visible over the
            same tripwire_event / panic_mode websocket stream every other
            event uses.

            Body (all optional):
              { "mode": "persist" | "sweep" | "trickle" | "flood",  (default "persist")
                "sleep": float,   # per-touch gap seconds (trickle/sweep/persist)
                "count": int,     # touches (trickle/sweep) or total (flood)
                "max_runtime": float }  # persist only — safety cap in seconds

            Defaults to "persist" on purpose: sweep/trickle/flood finish and
            exit almost immediately, so by the time a critical classification
            fires there's often nothing left for panic mode to act on.
            persist keeps running — like real malware would — so Suspend/
            Kill/Auto-escalate have a live process to actually contain, and
            you can watch that containment happen instead of just reading a
            dry-run log line.

            Returns immediately with the subprocess pid; it does not block
            waiting for the simulator to finish (persist mode never finishes
            on its own). Stop it with DELETE /simulate/<pid>, or let panic
            mode's own suspend/kill actually stop it once it trips a
            detection — the intended demo path.
            """
            body = request.get_json(silent=True) or {}
            mode = body.get("mode", "persist")
            if mode not in _SIMULATE_MODES:
                return jsonify({"error": f"mode must be one of {sorted(_SIMULATE_MODES)}"}), 400

            sim_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simulator.py")
            cmd = [sys.executable, sim_path, "--mode", mode]
            if body.get("sleep") is not None:
                cmd += ["--sleep", str(body["sleep"])]
            if body.get("count") is not None:
                cmd += ["--count", str(body["count"])]
            if mode == "persist" and body.get("max_runtime") is not None:
                cmd += ["--max-runtime", str(body["max_runtime"])]

            try:
                proc = subprocess.Popen(cmd, cwd=os.path.dirname(sim_path))
            except Exception as e:
                return jsonify({"error": f"failed to launch simulator: {e}"}), 500

            with self._sim_lock:
                self._sim_procs[proc.pid] = proc

            return jsonify({"pid": proc.pid, "mode": mode, "ok": True})

        @self.app.get("/simulate")
        def list_simulate():
            """Currently tracked simulator subprocesses launched via POST
            /simulate, and whether each is still running."""
            with self._sim_lock:
                items = [{"pid": pid, "alive": proc.poll() is None}
                         for pid, proc in self._sim_procs.items()]
            return jsonify({"processes": items})

        @self.app.delete("/simulate/<int:pid>")
        def stop_simulate(pid):
            """Stop a simulator subprocess started via POST /simulate — mainly
            needed for persist mode, which otherwise runs until something
            (panic mode, or this) stops it. Distinct from panic.py's
            suspend/kill: this is the dashboard's own "turn off the demo"
            control, not a detection response, so it always actually stops
            the process regardless of dry-run/allowlist state."""
            with self._sim_lock:
                proc = self._sim_procs.get(pid)
            if proc is None:
                return jsonify({"error": "no tracked simulator subprocess with that pid"}), 404
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            with self._sim_lock:
                self._sim_procs.pop(pid, None)
            return jsonify({"pid": pid, "stopped": True, "ok": True})

        @self.app.post("/config/dry-run")
        def set_dry_run():
            """
            Toggle panic dry-run.  Requires {"confirm": true} in body when
            arming (dry_run → False) so the web UI can show an explicit
            confirmation step before enabling live process actions.
            """
            body = request.get_json(silent=True) or {}
            enable_live = body.get("dry_run") is False   # dry_run=false means arm
            if enable_live and not body.get("confirm"):
                return jsonify({
                    "error": "set confirm=true to arm live mode — this enables real process suspension/kill",
                    "current_dry_run": self.panic.dry_run,
                }), 400
            self.panic.dry_run = not enable_live
            return jsonify({"dry_run": self.panic.dry_run, "ok": True})

        # ── case persistence ────────────────────────────────────────────
        # Backs the frontend's incidents.js: the dashboard rebuilds cases
        # from the raw event stream on every load, then merges in whatever
        # mutable state (status/notes/actionLog/panic linkage) was last
        # persisted here for that same case `key`.

        @self.app.get("/cases")
        def list_cases():
            return jsonify(self.store.list_cases())

        @self.app.post("/cases")
        def upsert_case():
            body = request.get_json(silent=True) or {}
            if not body.get("id") or not body.get("key"):
                return jsonify({"error": "case body must include 'id' and 'key'"}), 400
            try:
                saved = self.store.upsert_case(body)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return jsonify(saved)

        @self.app.get("/cases/<case_id>")
        def get_case(case_id):
            case = self.store.get_case(case_id)
            if case is None:
                return jsonify({"error": "no such case"}), 404
            return jsonify(case)

        @self.app.delete("/cases/<case_id>")
        def delete_case(case_id):
            deleted = self.store.delete_case(case_id)
            if not deleted:
                return jsonify({"error": "no such case"}), 404
            return jsonify({"id": case_id, "deleted": True})

        @self.app.delete("/cases")
        def clear_cases():
            """Wipe every persisted case. Used by the dashboard's full Reset
            so cleared/old incidents don't keep reappearing after a reload."""
            count = self.store.clear_cases()
            return jsonify({"deleted": count})

        @self.app.delete("/events")
        def clear_events():
            """
            Wipe event history — all of it, or (with ?before=<unix ts>) only
            rows older than a cutoff, so the activity feed doesn't have to be
            all-or-nothing. Used by the dashboard's full Reset.
            """
            before = request.args.get("before")
            before_ts = None
            if before is not None:
                try:
                    before_ts = float(before)
                except ValueError:
                    return jsonify({"error": "'before' must be a unix timestamp"}), 400
            count = self.store.clear_events(before_ts=before_ts)
            return jsonify({"deleted": count})

        @self.app.delete("/events/<int:event_id>")
        def delete_event(event_id):
            deleted = self.store.delete_event(event_id)
            if not deleted:
                return jsonify({"error": "no such event"}), 404
            return jsonify({"id": event_id, "deleted": True})

    # ── lifecycle ─────────────────────────────────────────────────────────

    def _start_fs_monitor(self) -> tuple[bool, Optional[str]]:
        """Idempotent: no-op if already running. Returns (ok, error)."""
        if self.fs_monitor and self.fs_monitor.is_alive():
            return True, None
        ok, reason = fanotify_watcher.is_available()
        if not ok:
            self.fs_monitor_error = reason
            return False, reason
        w = fanotify_watcher.FanotifyWatcher(
            mounts=config.FULL_SYSTEM_MONITOR_MOUNTS,
            callback=self._on_full_system_open,
            ignore_prefixes=config.FULL_SYSTEM_MONITOR_IGNORE_PREFIXES,
        )
        try:
            w.start()
        except (PermissionError, OSError) as e:
            self.fs_monitor_error = str(e)
            return False, str(e)
        self.fs_monitor = w
        self.fs_monitor_error = w.last_error()  # partial-mount failures, if any
        return True, None

    def _stop_fs_monitor(self):
        if self.fs_monitor:
            self.fs_monitor.stop()
            self.fs_monitor = None

    def start(self, ensure_decoys: bool = True):
        if ensure_decoys:
            summary = decoy_gen.generate_decoys()
            # Hot-load the full decoy path set into the watcher.
            self.watcher.refresh_known_paths(set(decoy_gen.all_decoy_paths()))
        self.snapshotter.start()
        self.watcher.start()
        if self.full_system_monitor_requested:
            ok, err = self._start_fs_monitor()
            if not ok:
                # Non-fatal: the decoy pipeline still works fine without
                # this. Surfaced via /health's fs_monitor_error instead of
                # crashing server startup over an optional, root-only feature.
                print(f"[fanotify] full-system monitor NOT started: {err}")
        self._health_stop.clear()
        self._health_thread = threading.Thread(
            target=self._health_tick_loop, daemon=True, name="tripwire-health"
        )
        self._health_thread.start()

    def stop(self):
        self._health_stop.set()
        if self._health_thread:
            self._health_thread.join(timeout=2)
        self.watcher.stop()
        self._stop_fs_monitor()
        self.snapshotter.stop()
        # Don't leak simulator subprocesses (especially persist mode, which
        # runs until something stops it) past the server's own lifetime.
        with self._sim_lock:
            procs = list(self._sim_procs.values())
            self._sim_procs.clear()
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self._orig_decoy_placements is not None:
            config.DECOY_PLACEMENTS = self._orig_decoy_placements
            config.MANIFEST_PATH    = self._orig_manifest_path
            self._orig_decoy_placements = None

    def run(self, host: str = config.SERVER_HOST, port: int = config.SERVER_PORT):
        self.start()
        try:
            self.socketio.run(self.app, host=host, port=port)
        finally:
            self.stop()


# ─── Self-test ────────────────────────────────────────────────────────────

def _run_self_test():
    import tempfile, shutil

    tmp = tempfile.mkdtemp()
    db  = os.path.join(tmp, "test.db")
    srv = TripwireServer(db_path=db, dry_run=True)

    # Give the watcher something to watch so is_alive() is meaningful
    srv.watcher.start()
    time.sleep(0.2)
    client = srv.app.test_client()

    try:
        # 1 ── /health baseline ──────────────────────────────────────────────
        print("[1/14] GET /health before any events ... ", end="", flush=True)
        r = client.get("/health")
        b = r.get_json()
        assert r.status_code == 200
        assert b["dead_letter_count"] == 0
        assert b["last_event_ts"] is None
        assert b["watcher_alive"] is True
        assert b["dry_run"] is True
        print(f"OK → {b}")

        # 2 ── synthetic event enrichment ────────────────────────────────────
        print("[2/14] synthetic event enriches payload with placement + recommended_action ... ", end="", flush=True)
        fake_path = os.path.join(config.HOME, "Desktop", "Passwords_Backup.txt")
        srv._on_fs_event("modify", fake_path, time.time())
        assert srv.store.count_events() == 1
        emitted_names = [n for n, _ in srv.socketio_emitted]
        assert "tripwire_event" in emitted_names
        payload = next(p for n, p in srv.socketio_emitted if n == "tripwire_event")
        assert "recommended_action" in payload
        assert "filename" in payload
        assert payload["filename"] == "Passwords_Backup.txt"
        print(f"OK → severity={payload['severity']}, recommendation={payload['recommended_action']!r}")

        # 3 ── dead-letter on bad event_type ─────────────────────────────────
        print("[3/14] malformed event dead-lettered, pipeline stays alive ... ", end="", flush=True)
        srv._on_fs_event("NOT_VALID", fake_path, time.time())
        assert srv.store.dead_letter_count() == 1
        assert srv.store.count_events() == 1   # bad event not stored as real
        print("OK")

        # 4 ── critical burst triggers panic_mode emit ────────────────────────
        print("[4/14] critical burst emits panic_mode with event_id link ... ", end="", flush=True)
        for i in range(config.CRITICAL_TOUCH_THRESHOLD + 2):
            srv._on_fs_event("modify", fake_path, time.time())
        panic_emits = [(n, p) for n, p in srv.socketio_emitted if n == "panic_mode"]
        assert len(panic_emits) >= 1
        pm = panic_emits[-1][1]
        assert pm["dry_run"] is True
        assert "event_id" in pm
        print(f"OK → dry_run={pm['dry_run']}, event_id={pm['event_id']}")

        # 5 ── GET /events ───────────────────────────────────────────────────
        print("[5/14] GET /events returns enriched history ... ", end="", flush=True)
        r2 = client.get("/events?limit=5")
        evs = r2.get_json()
        assert isinstance(evs, list) and len(evs) > 0
        assert "recommended_action" in evs[0]
        print(f"OK → {len(evs)} events returned")

        # 6 ── POST /config/dry-run requires confirm ──────────────────────────
        print("[6/14] POST /config/dry-run refuses to arm without confirm ... ", end="", flush=True)
        r3 = client.post("/config/dry-run",
                         data=json.dumps({"dry_run": False}),
                         content_type="application/json")
        assert r3.status_code == 400
        r4 = client.post("/config/dry-run",
                         data=json.dumps({"dry_run": False, "confirm": True}),
                         content_type="application/json")
        assert r4.status_code == 200
        assert r4.get_json()["dry_run"] is False
        # restore
        client.post("/config/dry-run",
                    data=json.dumps({"dry_run": True}),
                    content_type="application/json")
        print("OK → armed with confirm, disarmed again")

        # 7 ── POST /config/thresholds live update ───────────────────────────
        print("[7/14] POST /config/thresholds updates live ... ", end="", flush=True)
        r5 = client.post("/config/thresholds",
                         data=json.dumps({"warning": 2, "critical": 4}),
                         content_type="application/json")
        assert r5.status_code == 200
        assert config.WARNING_TOUCH_THRESHOLD == 2
        assert config.CRITICAL_TOUCH_THRESHOLD == 4
        print(f"OK → warning={config.WARNING_TOUCH_THRESHOLD}, critical={config.CRITICAL_TOUCH_THRESHOLD}")

        # 8 ── POST /action lock (this used to 500: lock_file() didn't exist) ──
        print("[8/14] POST /action {action: lock} succeeds (dry-run) ... ", end="", flush=True)
        r6 = client.post("/action",
                         data=json.dumps({"action": "lock"}),
                         content_type="application/json")
        assert r6.status_code == 200, r6.get_data(as_text=True)
        assert r6.get_json()["action"] == "lock"
        print(f"OK → {r6.get_json()}")

        # 9 ── GET /report returns a real PDF, even with just the events above ──
        print("[9/14] GET /report returns a downloadable PDF ... ", end="", flush=True)
        r7 = client.get("/report")
        assert r7.status_code == 200
        assert r7.mimetype == "application/pdf"
        assert len(r7.data) > 0
        print(f"OK → {len(r7.data)} bytes")

        # 10 ── /cases CRUD round-trip through the REST layer ──────────────────
        print("[10/14] /cases: POST upserts, GET lists/fetches, DELETE removes, 404 on missing ... ", end="", flush=True)
        case_body = {
            "id": "case-1", "key": "sim_attack.exe::4821", "status": "open",
            "title": "Suspicious activity — sim_attack.exe", "severity": "Critical",
            "notes": [{"id": "note-1", "text": "reviewing", "ts": "10:00:00"}],
            "actionLog": [], "backendDriven": False,
        }
        r8 = client.post("/cases", data=json.dumps(case_body), content_type="application/json")
        assert r8.status_code == 200, r8.get_data(as_text=True)
        assert r8.get_json()["notes"][0]["text"] == "reviewing"

        r9 = client.get("/cases")
        assert r9.status_code == 200
        assert any(c["id"] == "case-1" for c in r9.get_json())

        r10 = client.get("/cases/case-1")
        assert r10.status_code == 200
        assert r10.get_json()["status"] == "open"

        # missing required field → 400
        r11 = client.post("/cases", data=json.dumps({"id": "case-2"}), content_type="application/json")
        assert r11.status_code == 400

        r12 = client.delete("/cases/case-1")
        assert r12.status_code == 200
        assert r12.get_json()["deleted"] is True

        r13 = client.get("/cases/case-1")
        assert r13.status_code == 404
        r14 = client.delete("/cases/case-1")
        assert r14.status_code == 404
        print("OK")

        # 11 ── DELETE /cases wipes everything (full Reset) ────────────────────
        print("[11/14] DELETE /cases clears all persisted cases ... ", end="", flush=True)
        client.post("/cases", data=json.dumps({**case_body, "id": "case-a"}), content_type="application/json")
        client.post("/cases", data=json.dumps({**case_body, "id": "case-b", "key": "other::99"}), content_type="application/json")
        assert len(client.get("/cases").get_json()) == 2
        r15 = client.delete("/cases")
        assert r15.status_code == 200
        assert r15.get_json()["deleted"] == 2
        assert client.get("/cases").get_json() == []
        print("OK")

        # 12 ── DELETE /events wipes all, or only rows older than a cutoff ──────
        print("[12/14] DELETE /events clears history, respects ?before cutoff ... ", end="", flush=True)
        srv.store.insert_event(Event(event_type="read", file_path="decoys/old.txt", timestamp=100.0))
        srv.store.insert_event(Event(event_type="read", file_path="decoys/new.txt", timestamp=time.time()))
        before_clear_count = srv.store.count_events()
        assert before_clear_count >= 2

        r16 = client.delete("/events?before=not-a-number")
        assert r16.status_code == 400

        r17 = client.delete("/events?before=150.0")
        assert r17.status_code == 200
        assert r17.get_json()["deleted"] == 1  # only the ts=100.0 row
        assert srv.store.count_events() == before_clear_count - 1

        r18 = client.delete("/events")
        assert r18.status_code == 200
        assert srv.store.count_events() == 0
        print(f"OK → cutoff removed 1, full wipe removed the rest")

        # 13 ── DELETE /events/<id> removes exactly one row from the feed ──────
        print("[13/14] DELETE /events/<id> clears a single row, 404s on a missing/bad id ... ", end="", flush=True)
        eid_a = srv.store.insert_event(Event(event_type="read", file_path="decoys/a.txt", timestamp=time.time()))
        eid_b = srv.store.insert_event(Event(event_type="read", file_path="decoys/b.txt", timestamp=time.time()))
        assert srv.store.count_events() == 2

        r19 = client.delete(f"/events/{eid_a}")
        assert r19.status_code == 200
        assert r19.get_json()["deleted"] is True
        assert srv.store.count_events() == 1
        assert srv.store.get_event(eid_b) is not None

        r20 = client.delete(f"/events/{eid_a}")
        assert r20.status_code == 404  # already gone

        r21 = client.delete("/events/not-an-id")
        assert r21.status_code == 404  # Flask's <int:...> converter rejects non-numeric ids
        print("OK")

        # 14 ── CORS actually allows DELETE (regression guard for the bug where
        #       the after_request hook hardcoded GET/POST/OPTIONS and silently
        #       blocked every delete/reset call at the browser level) ─────────
        print("[14/14] CORS header allows DELETE, so browser-side deletes aren't silently blocked ... ", end="", flush=True)
        r22 = client.delete("/events")
        allowed_methods = r22.headers.get("Access-Control-Allow-Methods", "")
        assert "DELETE" in allowed_methods, f"DELETE missing from Access-Control-Allow-Methods: {allowed_methods!r}"
        print("OK")

        print(f"\n✓ All checks passed.  (flask_socketio installed: {_HAVE_SOCKETIO})")

    finally:
        srv.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def _cli():
    import argparse
    parser = argparse.ArgumentParser(description="Tripwire backend server.")
    parser.add_argument("--self-test", action="store_true",
                         help="run the built-in diagnostic self-test instead of the real server")
    parser.add_argument("--host", default=config.SERVER_HOST)
    parser.add_argument("--port", type=int, default=config.SERVER_PORT)
    parser.add_argument("--live", action="store_true",
                         help="disable Panic Mode dry-run (DANGEROUS: will really suspend/kill processes)")
    parser.add_argument("--full-system-monitor", action="store_true",
                         help="watch every file open() on config.FULL_SYSTEM_MONITOR_MOUNTS via "
                              "fanotify, not just decoy files (Linux + must run as root)")
    args = parser.parse_args()

    if args.self_test:
        _run_self_test()
        return

    srv = TripwireServer(dry_run=not args.live, full_system_monitor=args.full_system_monitor)
    srv.start()
    if args.full_system_monitor and not (srv.fs_monitor and srv.fs_monitor.is_alive()):
        print(f"[fanotify] WARNING: --full-system-monitor requested but not running "
              f"({srv.fs_monitor_error}). Try: sudo python3 server.py --full-system-monitor")
    print(f"Tripwire server starting on http://{args.host}:{args.port} "
          f"(dry_run={srv.panic.dry_run}) — Ctrl+C to stop")
    try:
        srv.socketio.run(srv.app, host=args.host, port=args.port)
    finally:
        srv.stop()


if __name__ == "__main__":
    _cli()
