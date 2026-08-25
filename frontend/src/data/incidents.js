/**
 * incidents.js
 *
 * Turns the flat event stream into stateful "cases" an analyst can actually
 * work: one row per distinct offending process, carrying its own evidence
 * timeline, status, notes, and action history. Before this module, the UI
 * only ever knew about a single global `incident` (whatever panic_mode last
 * reported), so a second suspicious process — or a second run of the demo —
 * had nowhere to go. Real triage means comparing several candidate incidents
 * and choosing what to do with each one independently.
 */

let _nextCaseSeq = 1;
let _nextEntrySeq = 1;

const OPEN_STATUSES = new Set(["open", "escalated"]);

/** Severity rank used to keep an incident's headline severity at its worst-seen value. */
const SEVERITY_RANK = { Critical: 2, Warning: 1, Normal: 0 };

function higherSeverity(a, b) {
  return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? a : b;
}

/** Groups events that belong together: same offending process + PID. */
function groupKey(event) {
  return `${event.process}::${event.pid}`;
}

function titleFor(event) {
  return event.severity === "Critical"
    ? `Suspicious activity — ${event.process}`
    : `Elevated activity — ${event.process}`;
}

function descriptionFor(event) {
  return event.severity === "Critical"
    ? "Rapid access across multiple protected resources has triggered a detection."
    : "Touch count is elevated but hasn't crossed the critical threshold yet.";
}

/**
 * Folds one new event into the current incident list, creating a case the
 * first time a process crosses into Warning/Critical and updating it
 * (evidence, severity, timestamps) on every later touch from that same
 * process. Normal events never open or touch a case.
 *
 * If a case for this process was already dismissed or contained, further
 * events from that same process do NOT reopen it as a fresh incident — they
 * just get logged onto the existing (still-closed) case's evidence trail.
 * Without this, an analyst dismissing/containing a case whose process was
 * still active (e.g. a still-running attacker script) would see it pop
 * right back up as a brand-new "open" card on the very next event, which
 * looked exactly like Dismiss/Clear doing nothing at all. The case only
 * reopens as fresh once it's fully removed from the queue (X / Clear
 * resolved) — at that point there's nothing left to update, so a new event
 * correctly starts a new case.
 *
 * Pure function: returns a new array, existing incident objects for
 * untouched cases are reused by reference so React can bail out of re-rendering them.
 */
export function foldEventIntoIncidents(incidents, event) {
  if (event.severityRaw === "info") return incidents;

  const key = groupKey(event);
  const idx = incidents.findIndex((inc) => inc.key === key);

  if (idx === -1) {
    const created = {
      id: `case-${_nextCaseSeq++}`,
      key,
      process: event.process,
      pid: event.pid,
      parentProcess: event.parentProcess,
      parentPid: event.parentPid,
      severity: event.severity,
      mitre: event.mitre,
      title: titleFor(event),
      description: descriptionFor(event),
      status: "open", // open | contained | dismissed | escalated
      firstSeen: event.time,
      lastSeen: event.time,
      eventIds: [event.id],
      notes: [],
      actionLog: [],
      backendDriven: false,
    };
    return [created, ...incidents];
  }

  return incidents.map((inc, i) => {
    if (i !== idx) return inc;
    if (!OPEN_STATUSES.has(inc.status)) {
      // Already dismissed/contained — keep the resolution, just extend the
      // evidence trail quietly so the record stays complete.
      return { ...inc, lastSeen: event.time, eventIds: [...inc.eventIds, event.id] };
    }
    return {
      ...inc,
      severity: higherSeverity(inc.severity, event.severity),
      mitre: event.mitre || inc.mitre,
      lastSeen: event.time,
      eventIds: [...inc.eventIds, event.id],
      title: higherSeverity(inc.severity, event.severity) === "Critical" ? titleFor(event) : inc.title,
    };
  });
}

/** Builds the full derived-incident list from a whole event array (used by the demo/reset paths). */
export function buildIncidentsFromEvents(events) {
  // Fold oldest-first so lastSeen/evidence order matches arrival order.
  return [...events].reverse().reduce(foldEventIntoIncidents, []);
}

export function addNote(incidents, incidentId, text) {
  const trimmed = text.trim();
  if (!trimmed) return incidents;
  return incidents.map((inc) =>
    inc.id === incidentId
      ? {
          ...inc,
          notes: [
            ...inc.notes,
            { id: `note-${_nextEntrySeq++}`, text: trimmed, ts: new Date().toLocaleTimeString() },
          ],
        }
      : inc
  );
}

// `backendSupported: true` means this action is actually wired to
// POST /action and can really suspend/kill a process (see
// useTripwireConnection.js's respondToIncident). "isolate" and "escalate"
// have no corresponding backend endpoint — the wire contract only knows
// suspend/kill/lock — so they're labeled "(logged only)" rather than
// implying a host actually got cut off the network or a ticket was filed.
export const RESPONSE_ACTIONS = {
  suspend: {
    label: "Suspend process",
    verb: "Suspend logged",
    resultStatus: "contained",
    backendSupported: true,
    before: (inc) => `${inc.process} (PID ${inc.pid}) — running`,
    after: (inc, dryRun) =>
      dryRun
        ? "Suspend logged (dry run) — process left running"
        : `${inc.process} (PID ${inc.pid}) — suspended`,
  },
  kill: {
    label: "Kill process",
    verb: "Kill logged",
    resultStatus: "contained",
    backendSupported: true,
    before: (inc) => `${inc.process} (PID ${inc.pid}) — running`,
    after: (inc, dryRun) =>
      dryRun
        ? "Kill logged (dry run) — process left running"
        : `${inc.process} (PID ${inc.pid}) — terminated`,
  },
  isolate: {
    label: "Isolate host (logged only)",
    verb: "Isolation logged",
    resultStatus: "contained",
    backendSupported: false,
    before: () => "Host — on network",
    after: () =>
      "Isolation logged — no backend endpoint exists yet, host was NOT actually cut off the network",
  },
  escalate: {
    label: "Escalate to SOC (logged only)",
    verb: "Escalation logged",
    resultStatus: "escalated",
    backendSupported: false,
    before: (inc) => `${inc.title} — unassigned`,
    after: () => "Escalated locally — no ticketing system is wired up to notify SOC",
  },
  dismiss: {
    label: "Dismiss as false positive",
    verb: "Dismissal logged",
    resultStatus: "dismissed",
    backendSupported: false,
    before: (inc) => `${inc.title} — open`,
    after: () => "Marked as false positive — no further action",
  },
};

/**
 * Applies a response action to one incident, appending an entry to its
 * action log.
 *
 * Backend-supported actions (suspend/kill) do NOT get to claim their
 * resultStatus ("contained") just because the button was clicked — that
 * used to happen unconditionally here, which meant the case flipped to
 * "Contained" the instant you clicked Kill even in dry-run, even if the
 * fetch to POST /action never arrived, and even if it failed. The only
 * real source of truth is the backend's response_ack (see onResponseAck in
 * useTripwireConnection.js), so backend-supported actions instead mark the
 * case `pendingAction` and leave status untouched until that ack resolves
 * it. Locally-only actions (isolate/escalate/dismiss) have no ack to wait
 * for, so they still resolve immediately.
 */
export function respondToIncident(incidents, incidentId, actionKey, dryRun) {
  const action = RESPONSE_ACTIONS[actionKey];
  if (!action) return { incidents, result: null };

  let result = null;

  const next = incidents.map((inc) => {
    if (inc.id !== incidentId) return inc;
    const before = action.before(inc);
    const after = action.after(inc, dryRun);
    result = { before, after, ts: new Date().toLocaleTimeString(), action: action.label };
    return {
      ...inc,
      status: action.backendSupported ? inc.status : action.resultStatus,
      pendingAction: action.backendSupported ? actionKey : inc.pendingAction ?? null,
      actionLog: [
        ...inc.actionLog,
        {
          id: `action-${_nextEntrySeq++}`,
          label: action.label,
          before,
          after,
          ts: result.ts,
          dryRun,
          pending: action.backendSupported,
        },
      ],
    };
  });

  return { incidents: next, result };
}

/**
 * Merges backend-reported panic_mode context onto the matching (by pid) open
 * incident, including the backend's authoritative mitigation_status —
 * "auto_mitigated" (a real action actually succeeded) or "requires_manual"
 * (dry-run / nothing succeeded / monitor-only rule) — rather than the
 * frontend re-deriving that from a raw dry_run flag. escalation=true means
 * this specific panic_mode event was fired by the auto-escalate-to-kill path
 * (the process kept touching decoys after being suspended), which gets its
 * own description so an analyst can tell "first response" apart from
 * "we had to escalate."
 */
export function attachBackendPanic(incidents, panic, lastCriticalEvent) {
  if (!lastCriticalEvent) return incidents;
  const key = `${lastCriticalEvent.process}::${lastCriticalEvent.pid}`;
  let matched = false;

  const mitigationStatus = panic.mitigation_status
    ?? (panic.dry_run ? "requires_manual" : "auto_mitigated");

  const description = panic.escalation
    ? (panic.escalation_reason
        || "Process kept touching decoys after being suspended — auto-escalated to kill.")
    : mitigationStatus === "auto_mitigated"
      ? "Rapid access across multiple protected resources has triggered a detection. Panic Mode suspended the source process and locked protected resources."
      : "Rapid access across multiple protected resources has triggered a detection. Panic Mode ran in dry-run mode (or the response rule was monitor-only) — no process was actually suspended. Manual action is needed.";

  const next = incidents.map((inc) => {
    if (inc.key !== key || !OPEN_STATUSES.has(inc.status)) return inc;
    matched = true;
    return {
      ...inc,
      backendDriven: true,
      suspended: panic.suspended || [],
      killed: panic.killed ?? null,
      dryRun: panic.dry_run,
      mitigationStatus,
      escalated: panic.escalation === true || inc.escalated === true,
      description,
    };
  });

  return matched ? next : incidents;
}

/** Removes a single incident from the list — e.g. an old resolved case an analyst wants off the queue. */
export function removeIncident(incidents, incidentId) {
  return incidents.filter((inc) => inc.id !== incidentId);
}

/** Bulk-removes every case that's already been resolved (contained or dismissed), leaving open/escalated work untouched. */
export function clearResolvedIncidents(incidents) {
  return incidents.filter((inc) => inc.status === "open" || inc.status === "escalated");
}

// ─── Backend persistence bridge ─────────────────────────────────────────
//
// Incidents are rebuilt from the raw event stream on every load
// (buildIncidentsFromEvents) — that's what gives them their identity
// (process + pid) and evidence timeline. But the *mutable*, analyst-driven
// part of a case — status, notes, action log, backend panic linkage — only
// ever lived in memory, so a page refresh silently wiped every note written
// and every action logged. These helpers bridge that gap against the
// backend's /cases store.
//
// IDs are NOT a safe join key: `_nextCaseSeq` restarts at 1 on every reload
// of this module, so the same real-world case can get a different id
// across two rebuilds. `key` (process::pid) is stable across rebuilds and
// is what both sides persist/merge on.

/** Fields that represent analyst/backend-driven mutable state — not stuff re-derived from events. */
const MUTABLE_CASE_FIELDS = [
  "status",
  "title",
  "description",
  "severity",
  "mitre",
  "notes",
  "actionLog",
  "backendDriven",
  "suspended",
  "killed",
  "dryRun",
];

/** Extracts just the persistable, mutable slice of one incident's state (matches the backend's case shape). */
export function serializeCaseState(incident) {
  const state = { id: incident.id, key: incident.key };
  for (const field of MUTABLE_CASE_FIELDS) {
    if (incident[field] !== undefined) state[field] = incident[field];
  }
  return state;
}

/** Serializes every incident's mutable state — the payload to POST to /cases after any change. */
export function serializeAllCaseStates(incidents) {
  return incidents.map(serializeCaseState);
}

/**
 * Merges persisted case states (as returned by GET /cases) onto a
 * freshly-rebuilt incident list, joining on `key` rather than `id` (see
 * note above). Only overwrites the mutable fields — identity and evidence
 * fields (process, pid, eventIds, firstSeen, lastSeen, ...) always come
 * from the freshly-rebuilt incident, since those are re-derived from the
 * current event log and a stored copy could be stale relative to it.
 * Cases with no stored state (never persisted, or opened since the last
 * save) pass through unchanged. Existing incident objects are reused by
 * reference when nothing changed, so React can bail out of re-rendering them.
 *
 * A case whose stored status is "removed" (a tombstone — see removeIncident
 * in the connection hook) is dropped from the result entirely. Without
 * this, deleting an incident only ever deleted the analyst's notes/status
 * row — incidents are always rebuilt from the raw event log, so on the
 * very next reload the same process's old events would rebuild it fresh
 * as a brand-new "open" case, making deletion look like it never happened.
 */
export function applyStoredCaseStates(incidents, storedStates) {
  if (!storedStates || storedStates.length === 0) return incidents;
  const byKey = new Map(storedStates.map((s) => [s.key, s]));

  const merged = incidents.map((inc) => {
    const stored = byKey.get(inc.key);
    if (!stored) return inc;

    let changed = false;
    const next = { ...inc };
    // Adopt the persisted id, not the freshly-generated one: `_nextCaseSeq`
    // restarts at 1 every reload, so without this, saving a note or status
    // change after a reload would POST a *new* id for the same real-world
    // case — leaving the old row behind as an orphan and quietly piling up
    // duplicate case rows in the backend on every refresh.
    if (stored.id && stored.id !== inc.id) {
      next.id = stored.id;
      changed = true;
    }
    for (const field of MUTABLE_CASE_FIELDS) {
      if (stored[field] !== undefined && stored[field] !== inc[field]) {
        next[field] = stored[field];
        changed = true;
      }
    }
    return changed ? next : inc;
  });

  return merged.filter((inc) => byKey.get(inc.key)?.status !== "removed");
}

/** Sort order for the incident queue: open work first, then by severity, then most recent. */
export function sortIncidents(incidents) {
  const statusRank = { open: 0, escalated: 1, contained: 2, dismissed: 3 };
  return [...incidents].sort((a, b) => {
    if (statusRank[a.status] !== statusRank[b.status]) return statusRank[a.status] - statusRank[b.status];
    if (SEVERITY_RANK[b.severity] !== SEVERITY_RANK[a.severity])
      return (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    return 0;
  });
}
