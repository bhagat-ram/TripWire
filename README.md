# 🪤 Tripwire

**Tripwire is a decoy-file intrusion detection system.** It scatters fake
"sensitive" files (SSNs, tax returns, VPN configs, board minutes...) across
real folders on your machine — `~/Desktop`, `~/Documents`, `~/Downloads`,
`/tmp`, etc. No legitimate program or user ever has a reason to touch these
files. So the moment *anything* reads, writes, renames, or deletes one, that
touch is treated as a hostile signal — the system figures out which process
did it, scores how dangerous it looks, can automatically shut that process
down, and shows you everything on a live dashboard.

Think of it like a home alarm system, but for your filesystem: the "decoys"
are the trip-wires, and touching one sets off the alarm.

---

## 1. The idea in plain English

1. **Plant fake bait.** Realistic-looking sensitive files get dropped in
   places a snooper or piece of ransomware would naturally look.
2. **Watch the bait, not the whole disk.** Instead of monitoring every file
   on the system (slow, noisy), Tripwire only watches the decoy files. Since
   nothing legitimate should ever open them, *any* activity is suspicious by
   definition — no false-positive tuning needed.
3. **Figure out who did it.** When a decoy is touched, Tripwire matches that
   moment against a snapshot of running processes to identify the culprit
   PID.
4. **Decide how bad it is.** A scoring engine looks at how many decoys were
   touched, how fast, and what kind of files they were, then labels the
   event `info`, `warning`, or `critical`, and tags it with the matching
   MITRE ATT&CK technique.
5. **Respond.** Depending on severity, Tripwire can automatically suspend,
   kill, or lock out the offending process — or just log it, if you keep it
   in safe "dry-run" mode (the default).
6. **Show it to a human.** A live React dashboard streams every event in
   real time, groups related events into "incidents" an analyst can
   investigate, and lets them respond manually or generate a PDF report.

---

## 2. How the pieces connect

```
 decoy_gen.py  →  watcher.py  →  attribution.py  →  classifier.py  →  panic.py
   (Stage 1)        (Stage 2)       (Stage 3)          (Stage 4)       (Stage 5)
   plants the       notices a       maps the           scores          auto-contains
   decoy files      file touch      touch to a PID     severity        the process
                                                                            │
                                                                            ▼
                                                                      server.py
                                                                (Stage 6 — REST + WebSocket)
                                                                            │
                                                                            ▼
                                                                    React dashboard
                                                                      (frontend/)
```

Each stage is a separate, single-purpose module:

| Stage | File | What it does |
|---|---|---|
| 1 | `decoy_gen.py` | Creates realistic decoy files at real filesystem locations — never inside a folder Tripwire itself uses. Running it twice won't duplicate or overwrite files; if a decoy's content has changed since it was planted, that change *is* evidence, so it's never silently overwritten. |
| 2 | `watcher.py` | Watches every decoy location using native OS file-event APIs (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) via `watchdog`, plus a polling fallback so nothing slips through if the OS event API misses something. Events are debounced so a burst of touches doesn't flood the pipeline. |
| 3 | `attribution.py` | Keeps a rolling snapshot of running processes and diffs it to figure out which PID most likely touched a given decoy. If it's genuinely ambiguous, it says so rather than guessing. |
| 4 | `classifier.py` | Scores each incident using a sliding time window (`info` / `warning` / `critical`) and tags it with a MITRE ATT&CK technique. Window state is saved to SQLite so a mid-burst crash doesn't lose the count. |
| 5 | `panic.py` | The automatic containment layer — suspends, kills, or locks a process based on severity. Every action is logged as *attempted → succeeded/failed*, safe to call twice, checks a fresh (never cached) allowlist before acting, and defaults to **dry-run** until explicitly armed. |
| — | `events.py` | The SQLite persistence layer: raw events, a dead-letter table for malformed payloads, the classifier's sliding window, and saved case state for the dashboard. |
| 6 | `server.py` | Flask + Socket.IO server. Exposes the REST API and pushes live events (`tripwire_event`, `panic_mode`, `health_tick`) over WebSocket. |
| — | `report.py` | Turns event history into a downloadable PDF incident report. |
| — | `simulator.py` | A safe test harness that only ever touches decoys Tripwire itself created, so you can generate realistic activity (`trickle`, `sweep`, `flood` modes) and exercise the whole pipeline without any real risk. |
| — | `frontend/` | The React + Vite dashboard: live activity feed, an incident queue built from events, per-incident notes and actions, and manual suspend/kill/lock controls — all wired to the backend over REST and WebSocket. |

---

## 3. How an "incident" becomes a card on the dashboard

This is the part that's easy to get wrong, so it's worth explaining clearly:

- The dashboard **does not store incidents directly.** Every time it loads,
  it rebuilds them from scratch out of the raw event log
  (`buildIncidentsFromEvents`), grouping consecutive events from the same
  process into one case. This guarantees the incident list is always
  consistent with the underlying evidence — there's no separate "incidents
  table" that can drift out of sync.
- What *can't* be rebuilt from events is the analyst's own work: a case's
  status (open / contained / dismissed / escalated), its notes, its action
  log, and whether panic.py already suspended/killed it. That part is
  genuinely stateful, so it's saved separately in the backend's `cases`
  table and merged back onto the freshly-rebuilt incidents by a stable
  `key` — not by `id`, which is just a client-side counter that resets on
  every page reload.
- A case you've already dismissed or contained **stays that way**, even if
  its process is still doing things — new events just extend its evidence
  trail quietly instead of popping back up as a duplicate "open" incident.
  It only becomes a fresh case again once it's fully removed from the queue.

---

## 4. REST API

| Method | Route | What it's for |
|---|---|---|
| GET | `/health` | Watcher status, dead-letter count, dry-run state |
| GET | `/events?limit=N` | Recent event history |
| DELETE | `/events?before=ts` | Clear event history — all, or older than a cutoff |
| DELETE | `/events/<id>` | Delete a single event row |
| GET | `/manifest` | Decoy placements and file list |
| GET | `/audit?limit=N` | `panic_actions.log`, as JSON |
| GET | `/report?limit=N` | Generate and download a PDF incident report |
| POST | `/action` | Trigger a manual response (suspend / kill / lock) |
| POST | `/config/thresholds` | Update the warning/critical thresholds live |
| POST | `/config/dry-run` | Toggle dry-run (requires `{"confirm": true}`) |
| GET | `/cases` | List saved case state |
| POST | `/cases` | Create or update a case (body needs `id` + `key`) |
| GET | `/cases/<id>` | Fetch one case |
| DELETE | `/cases/<id>` | Delete one case |
| DELETE | `/cases` | Delete every saved case |

**WebSocket events** pushed by the server: `tripwire_event`, `panic_mode`,
`health_tick`, `response_ack`.

---

## 5. Running it

**Backend** (Python 3.11+):
```bash
cd backend
pip install -r requirements.txt
python server.py
```

**Frontend**:
```bash
cd frontend
npm install       # or pnpm install
npm run dev
```

**Generate decoys** (safe — only writes to allowlisted paths):
```bash
cd backend
python decoy_gen.py
```

**Generate test activity** (never touches anything outside the decoys it
made itself — safe to run against a live setup):
```bash
python simulator.py --mode sweep    # or: trickle | flood
```

---

## 6. Tests

- **Built-in self-tests** — every backend module has a `--self-test` entry
  point you can run directly, and these are the primary reliability
  checkpoints kept green on every change:
  - `python events.py` → **9/9** passing (schema, event round-trip,
    dead-letter, touch windows, case CRUD, clear operations)
  - `python server.py --self-test` → **13/13** passing (health, events,
    manifest, audit, actions, thresholds, dry-run confirm gate, report PDF,
    full `/cases` CRUD + bulk clear, event clear/delete)
- **Pytest suites** in `tests/`:
  - `test_chaos.py` — full end-to-end reliability pass (kill mid-sweep,
    restart mid-incident, flood conditions)
  - `test_classifier.py` — severity scoring correctness
  - `test_panic_allowlist.py` — containment allowlist enforcement

  Run them with:
  ```bash
  pytest tests/
  ```

---

## 7. Safety guardrails

Tripwire touches real processes and real files, so it's built with several
layers of "don't shoot yourself in the foot":

- **Path allowlisting.** Every write path (`decoy_gen`, and `panic`'s lock
  action) checks `config.is_path_allowed()` first. Writes are confined to
  `HOME`, `/tmp`, and `/var/tmp`; system directories (`/etc`, `/usr`,
  `/bin`, `/proc`, etc.) are always refused, no exceptions.
- **Dry-run by default.** `panic.py` never actually suspends or kills
  anything until you explicitly arm it with `POST /config/dry-run` and
  `{"confirm": true}`. Until then, it only logs what it *would* have done.
- **A contained blast radius for testing.** `simulator.py` only ever
  touches paths that `decoy_gen` itself created — it will never read or
  write `real_data/` or anything outside the manifest, so you can safely
  run it against a live setup to see the pipeline work end to end.

---

## 8. Recent changes (this session)

- Added full `cases` persistence (backend table + CRUD + REST routes) so an
  analyst's status, notes, action log, and panic-linkage survive a page
  reload.
- Wired the frontend to actually call that persistence layer on every
  action (suspend / kill / dismiss / notes), instead of only updating local
  state.
- Fixed a bug where a dismissed/contained case whose process was still
  active would silently reopen as a duplicate incident on the next event —
  which made the "clear a case" action look broken.
- Added `DELETE /events`, `DELETE /events/<id>`, and `DELETE /cases` so the
  dashboard's Reset button and per-row/per-case removal actually clear
  backend history, not just local UI state.
- Exposed the event's real backend row `id` over the wire (previously
  stripped), so individual activity-feed rows can now be deleted
  individually.
