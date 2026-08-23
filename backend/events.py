"""
events.py — Stage 0
Event schema + SQLite persistence layer.

Reliability checkpoint this file must pass:
  - SQLite table created
  - Event round-trips through to_json/from_row without loss
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, asdict, field
from typing import Optional

import config


# ─── Schema ────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    attribution_confidence TEXT,
    parent_pid INTEGER,
    parent_name TEXT,
    severity TEXT,
    mitre_id TEXT,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dead_letter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_payload TEXT NOT NULL,
    error TEXT,
    received_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS recent_touches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS panic_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 1,
    started_at REAL,
    suspended_pids TEXT,
    killed_pid INTEGER
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    title TEXT,
    description TEXT,
    severity TEXT,
    mitre TEXT,
    notes TEXT NOT NULL DEFAULT '[]',
    action_log TEXT NOT NULL DEFAULT '[]',
    backend_driven INTEGER NOT NULL DEFAULT 0,
    suspended TEXT,
    killed INTEGER,
    dry_run INTEGER,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_touches_ts ON recent_touches(ts);
CREATE INDEX IF NOT EXISTS idx_cases_key ON cases(key);
"""

VALID_EVENT_TYPES = {"read", "rename", "delete", "modify"}
VALID_SEVERITIES = {"info", "warning", "critical", None}
VALID_CONFIDENCE = {"high", "ambiguous", "unknown", None}


# ─── Event dataclass — mirrors the frontend WebSocket contract exactly ─────

@dataclass
class Event:
    event_type: str
    file_path: str
    pid: Optional[int] = None
    process_name: Optional[str] = "unknown"
    attribution_confidence: Optional[str] = "unknown"
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    severity: Optional[str] = "info"
    mitre_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    id: Optional[int] = None  # populated after insert

    def __post_init__(self):
        if self.event_type not in VALID_EVENT_TYPES:
            raise ValueError(f"invalid event_type: {self.event_type!r}")
        if self.attribution_confidence not in VALID_CONFIDENCE:
            raise ValueError(f"invalid attribution_confidence: {self.attribution_confidence!r}")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Event":
        return cls(
            id=row["id"],
            event_type=row["event_type"],
            file_path=row["file_path"],
            pid=row["pid"],
            process_name=row["process_name"],
            attribution_confidence=row["attribution_confidence"],
            parent_pid=row["parent_pid"],
            parent_name=row["parent_name"],
            severity=row["severity"],
            mitre_id=row["mitre_id"],
            timestamp=row["timestamp"],
        )


# ─── Persistence layer ──────────────────────────────────────────────────────

class EventStore:
    """Thin, defensive wrapper around SQLite. Safe to construct repeatedly."""

    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # survives a crash mid-write better than default
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self):
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO panic_state (id, active, dry_run) VALUES (1, 0, 1)"
            )
            conn.commit()
        finally:
            conn.close()

    # ── events ──
    def insert_event(self, event: Event) -> int:
        conn = self._connect()
        try:
            cur = conn.execute(
                """INSERT INTO events
                   (event_type, file_path, pid, process_name, attribution_confidence,
                    parent_pid, parent_name, severity, mitre_id, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_type, event.file_path, event.pid, event.process_name,
                    event.attribution_confidence, event.parent_pid, event.parent_name,
                    event.severity, event.mitre_id, event.timestamp,
                ),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_event(self, event_id: int) -> Optional[Event]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            return Event.from_row(row) if row else None
        finally:
            conn.close()

    def recent_events(self, limit: int = 100) -> list[Event]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [Event.from_row(r) for r in rows]
        finally:
            conn.close()

    def count_events(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        finally:
            conn.close()

    # ── dead letter (used by server.py Stage 6, table lives here) ──
    def insert_dead_letter(self, raw_payload: str, error: str) -> int:
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO dead_letter (raw_payload, error, received_at) VALUES (?, ?, ?)",
                (raw_payload, error, time.time()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def dead_letter_count(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) AS c FROM dead_letter").fetchone()["c"]
        finally:
            conn.close()

    # ── recent_touches (classifier's persisted sliding window, Stage 4) ──
    def add_touch(self, file_path: str, ts: float):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO recent_touches (file_path, ts) VALUES (?, ?)", (file_path, ts)
            )
            conn.commit()
        finally:
            conn.close()

    def touches_since(self, since_ts: float) -> list[tuple[str, float]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT file_path, ts FROM recent_touches WHERE ts >= ? ORDER BY ts",
                (since_ts,),
            ).fetchall()
            return [(r["file_path"], r["ts"]) for r in rows]
        finally:
            conn.close()

    def prune_touches_before(self, cutoff_ts: float):
        conn = self._connect()
        try:
            conn.execute("DELETE FROM recent_touches WHERE ts < ?", (cutoff_ts,))
            conn.commit()
        finally:
            conn.close()

    # ── cases (frontend's persisted incident state, Stage 7) ──────────────
    #
    # A "case" mirrors the frontend's incident object (see incidents.js).
    # Only the analyst-mutable slice is stored here — status, notes, action
    # log, panic linkage — since the identity/evidence fields (process, pid,
    # eventIds, firstSeen, ...) are re-derived from the events table on every
    # reload. `key` (process::pid) is what the frontend joins on, not `id`,
    # because the frontend's case-id counter isn't stable across reloads.

    @staticmethod
    def _case_row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "key": row["key"],
            "status": row["status"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "mitre": row["mitre"],
            "notes": json.loads(row["notes"]),
            "actionLog": json.loads(row["action_log"]),
            "backendDriven": bool(row["backend_driven"]),
            "suspended": json.loads(row["suspended"]) if row["suspended"] is not None else None,
            "killed": row["killed"],
            "dryRun": None if row["dry_run"] is None else bool(row["dry_run"]),
            "updated_at": row["updated_at"],
        }

    def upsert_case(self, case: dict) -> dict:
        """Insert a new case or overwrite an existing one (matched by id).
        Accepts the frontend's case shape (or serializeCaseState's subset of
        it) and fills in sane defaults for anything missing."""
        if not case.get("id"):
            raise ValueError("case dict must include 'id'")
        if not case.get("key"):
            raise ValueError("case dict must include 'key'")

        now = time.time()
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO cases
                   (id, key, status, title, description, severity, mitre,
                    notes, action_log, backend_driven, suspended, killed, dry_run, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       key=excluded.key, status=excluded.status, title=excluded.title,
                       description=excluded.description, severity=excluded.severity,
                       mitre=excluded.mitre, notes=excluded.notes, action_log=excluded.action_log,
                       backend_driven=excluded.backend_driven, suspended=excluded.suspended,
                       killed=excluded.killed, dry_run=excluded.dry_run, updated_at=excluded.updated_at""",
                (
                    case["id"], case["key"], case.get("status", "open"),
                    case.get("title"), case.get("description"), case.get("severity"),
                    case.get("mitre"), json.dumps(case.get("notes", [])),
                    json.dumps(case.get("actionLog", [])), int(bool(case.get("backendDriven", False))),
                    json.dumps(case["suspended"]) if case.get("suspended") is not None else None,
                    case.get("killed"),
                    None if case.get("dryRun") is None else int(bool(case["dryRun"])),
                    now,
                ),
            )
            conn.commit()
            return self.get_case(case["id"])
        finally:
            conn.close()

    def get_case(self, case_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            return self._case_row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_cases(self) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
            return [self._case_row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def delete_case(self, case_id: str) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def clear_cases(self) -> int:
        """Delete every persisted case. Used by the dashboard's full Reset."""
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM cases")
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    # ── history cleanup ────────────────────────────────────────────────────
    # The events table has no retention policy of its own — every fs touch
    # is kept forever unless something explicitly prunes it. clear_events
    # backs the dashboard's Reset action (wipe everything) and also supports
    # a rolling cutoff (wipe everything older than a timestamp) so it isn't
    # all-or-nothing.

    def clear_events(self, before_ts: Optional[float] = None) -> int:
        conn = self._connect()
        try:
            if before_ts is None:
                cur = conn.execute("DELETE FROM events")
            else:
                cur = conn.execute("DELETE FROM events WHERE timestamp < ?", (before_ts,))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def delete_event(self, event_id: int) -> bool:
        """Delete a single event row — e.g. an analyst clearing one noisy/irrelevant row
        out of the activity feed rather than wiping the whole history."""
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


# ─── Self-test: reliability checkpoint ──────────────────────────────────────

def _run_self_test():
    import tempfile, os as _os

    tmp_dir = tempfile.mkdtemp()
    test_db = _os.path.join(tmp_dir, "test_tripwire.db")
    store = EventStore(db_path=test_db)

    print(f"[1/9] schema created at {test_db} ... ", end="")
    assert _os.path.exists(test_db)
    print("OK")

    print("[2/9] round-trip a full event through to_json/from_row ... ", end="")
    original = Event(
        event_type="read",
        file_path="decoys/Salary_Details.xlsx",
        pid=4821,
        process_name="sim_attack.exe",
        attribution_confidence="high",
        parent_pid=4800,
        parent_name="bash",
        severity="critical",
        mitre_id="T1486",
        timestamp=1755999999.123,
    )
    as_json = original.to_json()
    reparsed = json.loads(as_json)
    eid = store.insert_event(original)
    fetched = store.get_event(eid)
    for f in ("event_type", "file_path", "pid", "process_name", "attribution_confidence",
              "parent_pid", "parent_name", "severity", "mitre_id", "timestamp"):
        assert getattr(fetched, f) == getattr(original, f), f"mismatch on {f}"
        assert reparsed[f] == getattr(original, f), f"json mismatch on {f}"
    # id is part of the wire contract now — the frontend needs it to delete a
    # single event out of the activity feed.
    assert fetched.to_dict()["id"] == eid
    print("OK")

    print("[3/9] round-trip an event with nulls (unattributed process) ... ", end="")
    sparse = Event(event_type="delete", file_path="decoys/Q3_Budget.xlsx")
    eid2 = store.insert_event(sparse)
    fetched2 = store.get_event(eid2)
    assert fetched2.pid is None and fetched2.process_name == "unknown"
    print("OK")

    print("[4/9] dead-letter table accepts malformed payloads ... ", end="")
    store.insert_dead_letter('{"broken": true', "json.decoder.JSONDecodeError")
    assert store.dead_letter_count() == 1
    print("OK")

    print("[5/9] recent_touches persist and query by time window ... ", end="")
    now = time.time()
    store.add_touch("decoys/a.txt", now - 1)
    store.add_touch("decoys/b.txt", now)
    touches = store.touches_since(now - 5)
    assert len(touches) == 2
    print("OK")

    print("[6/9] case CRUD round-trips notes/actionLog/booleans and supports update + delete ... ", end="")
    case = {
        "id": "case-1",
        "key": "sim_attack.exe::4821",
        "status": "open",
        "title": "Suspicious activity — sim_attack.exe",
        "description": "Rapid access across multiple protected resources.",
        "severity": "Critical",
        "mitre": "T1486",
        "notes": [{"id": "note-1", "text": "checking process tree", "ts": "10:00:01"}],
        "actionLog": [],
        "backendDriven": False,
        "suspended": None,
        "killed": None,
        "dryRun": None,
    }
    created = store.upsert_case(case)
    assert created["id"] == "case-1" and created["key"] == "sim_attack.exe::4821"
    assert created["notes"][0]["text"] == "checking process tree"
    assert created["backendDriven"] is False

    fetched = store.get_case("case-1")
    assert fetched == created

    # update: same id, mutated mutable fields — must overwrite in place, not duplicate
    case["status"] = "contained"
    case["backendDriven"] = True
    case["suspended"] = [4821]
    case["dryRun"] = True
    case["actionLog"] = [{"id": "action-1", "label": "Suspend process", "before": "running", "after": "suspended"}]
    updated = store.upsert_case(case)
    assert updated["status"] == "contained"
    assert updated["suspended"] == [4821]
    assert updated["dryRun"] is True
    assert len(store.list_cases()) == 1  # overwrote, didn't duplicate

    assert store.delete_case("case-1") is True
    assert store.get_case("case-1") is None
    assert store.delete_case("case-1") is False  # already gone — no error, just False
    print("OK")

    print("[7/9] clear_cases wipes every persisted case ... ", end="")
    store.upsert_case({**case, "id": "case-2", "key": "a::1"})
    store.upsert_case({**case, "id": "case-3", "key": "b::2"})
    assert len(store.list_cases()) == 2
    deleted = store.clear_cases()
    assert deleted == 2
    assert store.list_cases() == []
    print("OK")

    print("[8/9] clear_events wipes all, or only rows older than a cutoff ... ", end="")
    store.insert_event(Event(event_type="read", file_path="decoys/x.txt", timestamp=100.0))
    store.insert_event(Event(event_type="read", file_path="decoys/y.txt", timestamp=200.0))
    assert store.count_events() == 4  # 2 from earlier in this test + these 2
    pruned = store.clear_events(before_ts=150.0)
    assert pruned == 1  # only the ts=100.0 row
    assert store.count_events() == 3
    wiped = store.clear_events()
    assert wiped == 3
    assert store.count_events() == 0
    print("OK")

    print("[9/9] delete_event removes exactly one row, no-ops safely if already gone ... ", end="")
    e1 = store.insert_event(Event(event_type="read", file_path="decoys/p.txt", timestamp=10.0))
    e2 = store.insert_event(Event(event_type="read", file_path="decoys/q.txt", timestamp=20.0))
    assert store.count_events() == 2
    assert store.delete_event(e1) is True
    assert store.get_event(e1) is None
    assert store.get_event(e2) is not None
    assert store.count_events() == 1
    assert store.delete_event(e1) is False  # already gone
    print("OK")

    print(f"\nAll checks passed. Event count in DB: {store.count_events()}")
    _os.remove(test_db)
    try:
        _os.remove(test_db + "-wal")
        _os.remove(test_db + "-shm")
    except OSError:
        pass
    _os.rmdir(tmp_dir)


if __name__ == "__main__":
    _run_self_test()
