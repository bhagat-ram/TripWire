# Tripwire

A real-time honeypot / canary-file intrusion detection system. Decoy files
that look like sensitive data (SSNs, tax returns, VPN configs, board
minutes...) are seeded across real locations on disk — `~/Desktop`,
`~/Documents`, `~/Downloads`, `/tmp`, `~/.config`, etc. Nothing legitimate
should ever touch them, so any read/write/rename/delete on a decoy is treated
as a signal: the pipeline attributes it to a process, classifies its
severity, can automatically suspend/kill the offending process, and gives an
analyst a live dashboard to investigate and respond from.

## How it fits together

```
decoy_gen  →  watcher  →  attribution  →  classifier  →  panic
 (Stage 1)    (Stage 2)    (Stage 3)      (Stage 4)     (Stage 5)
  seeds        detects       maps          scores         auto-
  decoys       fs touches    touch→PID     severity      contains
                                                            ↓
                                                         server.py
                                                    (Stage 6 — REST + WS)
                                                            ↓
                                                    React dashboard
                                                     (frontend/)
```

- **`decoy_gen.py`** — generates realistic-looking decoy files at real
  filesystem locations (never inside a watched app folder), idempotently.
  Never overwrites a file whose content has diverged (that divergence *is*
  the evidence).
- **`watcher.py`** — watches every decoy location with both `watchdog`
  (inotify/FSEvents/ReadDirectoryChangesW) and a polling fallback, debounced,
  so bursts don't flood the pipeline and nothing gets missed if the OS event
  API drops something.
- **`attribution.py`** — a rolling process snapshot, diffed against itself,
  to attribute a file touch to the PID that most likely caused it. Ambiguous
  matches are surfaced, never silently guessed.
- **`classifier.py`** — a sliding-window severity scorer (`info` /
  `warning` / `critical`) with MITRE ATT&CK technique tagging. Window state
  is persisted in SQLite so a crash mid-burst doesn't lose the count.
- **`panic.py`** — the automatic containment layer: suspend, kill, or lock
  based on severity. Every action is logged as attempted → succeeded/failed,
  is idempotent (safe to call twice), respects an allowlist read fresh at
  call time (never cached), and defaults to **dry-run** (logs what it
  *would* do without doing it) until explicitly armed.
- **`events.py`** — the SQLite persistence layer: raw events, a dead-letter
  table for malformed payloads, the classifier's touch window, and
  persisted **case** state (see below) for the dashboard.
- **`server.py`** — Flask + Socket.IO. Serves REST endpoints and pushes
  `tripwire_event` / `panic_mode` / `health_tick` over WebSocket in real
  time.
- **`report.py`** — generates a PDF incident report from the event history.
- **`simulator.py`** — a safe, self-contained process that only ever
  touches decoys the system itself created, used to generate realistic
  activity (`trickle` / `sweep` / `flood` modes) for testing the full
  pipeline end to end without touching anything real.
- **`frontend/`** — a React + Vite dashboard: live activity feed, an
  incident queue derived from events, per-case notes/actions, and manual
  response controls (suspend/kill/lock), wired to the backend over REST +
  WebSocket.

## Incident/case model

The dashboard doesn't store incidents directly — it **rebuilds them from the
raw event stream** on every load (`buildIncidentsFromEvents`), grouping
consecutive events from the same `process::pid` into one case. That gives
identity and an evidence trail that's always consistent with the event log.

What *isn't* re-derivable from events is the analyst's own work on a case —
its status (open/contained/dismissed/escalated), notes, action log, and any
backend-driven panic linkage (suspended/killed/dry-run). That mutable slice
is persisted separately in the backend's `cases` table and merged back onto
the freshly-rebuilt incidents on load, joined by the case's stable `key`
(not its `id`, which is only a client-side sequence number that resets every
reload).

A case that's been dismissed or contained stays that way even if its process
is still active — further events from that process extend its evidence trail
quietly rather than reopening it as a duplicate "open" card. It only
resets back to a fresh, brand-new case once it's fully removed from the
queue.

## REST API

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | watcher status, dead-letter count, dry-run state |
| GET | `/events?limit=N` | recent event history |
| DELETE | `/events?before=ts` | clear event history — all, or older than a cutoff |
| DELETE | `/events/<id>` | delete a single event row |
| GET | `/manifest` | decoy placements + file list |
| GET | `/audit?limit=N` | `panic_actions.log` as JSON |
| GET | `/report?limit=N` | generate + download a PDF incident report |
| POST | `/action` | trigger a manual response (suspend/kill/lock) |
| POST | `/config/thresholds` | update warning/critical thresholds live |
| POST | `/config/dry-run` | toggle dry-run (requires `{"confirm": true}`) |
| GET | `/cases` | list persisted case state |
| POST | `/cases` | upsert a case (body needs `id` + `key`) |
| GET | `/cases/<id>` | fetch one case |
| DELETE | `/cases/<id>` | delete one case |
| DELETE | `/cases` | delete every persisted case |

WebSocket events pushed by the server: `tripwire_event`, `panic_mode`,
`health_tick`, `response_ack`.

## Running it

**Backend** (Python 3.11+):
```bash
cd backend
pip install flask flask-socketio flask-cors psutil watchdog reportlab
python server.py
```

**Frontend**:
```bash
cd frontend
npm install   # or pnpm install
npm run dev
```

**Generate decoys** (safe — only writes to allowlisted paths):
```bash
cd backend
python decoy_gen.py
```

**Drive activity for testing** (never touches anything outside the decoys
it created itself):
```bash
python simulator.py --mode sweep
```

## Tests & self-tests

- Every backend module (`events.py`, `server.py`, `classifier.py`,
  `panic.py`, `watcher.py`, `decoy_gen.py`, `report.py`, `simulator.py`) has
  a `--self-test` entry point runnable directly (`python events.py`,
  `python server.py --self-test`, etc.) — these are the primary reliability
  checkpoints and are kept green on every change:
  - `events.py`: **9/9** passing (schema, event round-trip, dead-letter,
    touch windows, case CRUD, clear_cases, clear_events, delete_event).
  - `server.py`: **13/13** passing (health, events, manifest, audit,
    actions, thresholds, dry-run confirm gate, report PDF, full `/cases`
    CRUD + bulk clear, event clear + single-event delete).
- `tests/` holds pytest suites: `test_chaos.py` (full end-to-end reliability
  pass — kill mid-sweep, restart mid-incident, flood), `test_classifier.py`,
  `test_panic_allowlist.py`. Run with `pytest tests/`.

## Safety notes

- Every write path (`decoy_gen`, `panic`'s lock action) checks
  `config.is_path_allowed()` first — writes are confined to `HOME`, `/tmp`,
  `/var/tmp`; system directories (`/etc`, `/usr`, `/bin`, `/proc`, etc.) are
  always refused.
- `panic.py` defaults to **dry-run**. Arming live suspend/kill requires an
  explicit `{"confirm": true}` to `POST /config/dry-run`.
- `simulator.py` only ever touches paths that `decoy_gen` itself created —
  it never reads/writes `real_data/` or anything outside the manifest.

## Recent changes (this session)

- Added full `cases` persistence (backend table + CRUD + REST routes) so an
  analyst's status/notes/action log/panic-linkage survive a page reload.
- Wired the frontend to actually call that persistence layer on every
  action (suspend/kill/dismiss/notes), not just update local state.
- Fixed a bug where a dismissed/contained case whose process was still
  active would silently reopen as a duplicate incident on the next event —
  which made "clearing" a case look like it wasn't working.
- Added `DELETE /events`, `DELETE /events/<id>`, and `DELETE /cases` so the
  dashboard's Reset button and per-row/per-case removal actually clear
  backend history instead of only clearing local UI state.
- Exposed the event's real backend row `id` over the wire (previously
  stripped) so individual activity-feed rows can be deleted.
