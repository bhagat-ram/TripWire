import { useEffect, useRef, useState } from "react";

import {
  connectTripwireSocket,
  pollHealth,
  mapTripwireEvent,
  BACKEND_URL,
} from "../services/tripwireSocket";
import { suspiciousEvents } from "../data/mockEvents";
import {
  foldEventIntoIncidents,
  buildIncidentsFromEvents,
  addNote as addNoteToIncidents,
  respondToIncident as respondToIncidentCase,
  attachBackendPanic,
  removeIncident as removeIncidentFromList,
  clearResolvedIncidents,
  serializeCaseState,
  applyStoredCaseStates,
} from "../data/incidents";

const DEFAULT_THRESHOLDS = { warning: 3, critical: 6 };
// Mirrors config.py's own defaults, just so the panel isn't visibly blank
// for the one render before GET /config/auto-response actually answers.
const DEFAULT_AUTO_RESPONSE_RULES = { info: ["monitor"], warning: ["monitor"], critical: ["suspend", "lock"] };
const DEFAULT_ESCALATE_AFTER_TOUCHES = 3;

/** Best-effort save of one case's mutable state to the backend — fire-and-forget,
 * since the local state (already updated by the caller) is the source of truth
 * for this render either way; a failed save just means the next successful one
 * (or the next reload's merge) catches it up. */
function persistCase(incident) {
  fetch(`${BACKEND_URL}/cases`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(serializeCaseState(incident)),
  }).catch(() => {});
}

function deleteEventFromBackend(eventId) {
  fetch(`${BACKEND_URL}/events/${encodeURIComponent(eventId)}`, { method: "DELETE" }).catch(() => {});
}

function clearAllEventsFromBackend() {
  fetch(`${BACKEND_URL}/events`, { method: "DELETE" }).catch(() => {});
}

/**
 * Owns every piece of state App.jsx previously held directly: the live
 * WebSocket connection to the backend, health polling, the event feed, and
 * the demo-mode simulate/reset actions. Also owns the interactive controls
 * added in the UI pass: adjustable detection thresholds, the dry-run
 * arm/disarm flow, and the "just arrived" flag used to pulse new rows.
 *
 * Incident handling is case-based rather than single-incident: every event
 * that crosses into Warning/Critical is folded into an `incidents` list
 * (see data/incidents.js) so multiple concurrent suspicious processes each
 * get their own case an analyst can select, investigate, and respond to
 * independently, instead of one global "the incident" slot.
 */
export function useTripwireConnection() {
  // Starts empty, not with mockEvents.initialEvents — those two fixture rows
  // (explorer.exe reading Salary_Details.xlsx / Q3_Budget_Forecast.xlsx at
  // fixed timestamps) used to render as if they were real recent activity
  // even when the backend had no such history. Real history is fetched from
  // GET /events below once the backend answers; until then, "no activity
  // yet" is the honest state, not fabricated rows.
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [health, setHealth] = useState(null);
  const [thresholds, setThresholdsState] = useState(DEFAULT_THRESHOLDS);
  const [thresholdUpdateError, setThresholdUpdateError] = useState(null);
  const [autoResponseRules, setAutoResponseRulesState] = useState(DEFAULT_AUTO_RESPONSE_RULES);
  const [escalateAfterTouches, setEscalateAfterTouchesState] = useState(DEFAULT_ESCALATE_AFTER_TOUCHES);
  const [autoResponseUpdateError, setAutoResponseUpdateError] = useState(null);
  const [autoResponsePending, setAutoResponsePending] = useState(false);
  const [dryRunPending, setDryRunPending] = useState(false);
  const [lastArrivedId, setLastArrivedId] = useState(null);
  const [lastActionResult, setLastActionResult] = useState(null);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [simulationRunning, setSimulationRunning] = useState(false);
  const [simulationPid, setSimulationPid] = useState(null);
  const [simulationError, setSimulationError] = useState(null);

  const lastCriticalEventRef = useRef(null);

  // Load real backend history once on mount so the feed reflects actual past
  // activity (GET /events) instead of starting blank or with fake rows.
  // 500 is the actual ceiling server.py's /events route enforces
  // (`min(limit, 500)`) — asking for less than that here would silently cap
  // the feed below what the backend is willing to give us. There's no
  // offset/cursor param on /events, so history beyond the most recent 500
  // isn't reachable from this endpoint at all; SQLite still has everything,
  // it's just not exposed past that ceiling yet.
  useEffect(() => {
    let cancelled = false;
    Promise.all([
      fetch(`${BACKEND_URL}/events?limit=500`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      // Persisted mutable case state (status/notes/actionLog/panic linkage)
      // — merged onto the freshly-rebuilt incidents below so a refresh
      // doesn't wipe out notes or already-actioned cases.
      fetch(`${BACKEND_URL}/cases`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      // Current auto-response rules — config.py's live values may already
      // differ from the DEFAULT_* constants above (e.g. a previous session
      // changed them, or the backend was started with env overrides), so
      // the settings panel should reflect reality, not just the fallback.
      fetch(`${BACKEND_URL}/config/auto-response`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ])
      .then(([rawEvents, rawCases, rawAutoResponse]) => {
        if (cancelled) return;
        if (rawAutoResponse) {
          if (rawAutoResponse.rules) setAutoResponseRulesState(rawAutoResponse.rules);
          if (typeof rawAutoResponse.escalate_to_kill_after_touches === "number") {
            setEscalateAfterTouchesState(rawAutoResponse.escalate_to_kill_after_touches);
          }
        }
        if (!rawEvents) return;
        // Backend returns newest-first; keep that order to match how live
        // events get prepended below.
        const mapped = rawEvents.map(mapTripwireEvent);
        setEvents(mapped);
        const built = buildIncidentsFromEvents(mapped);
        setIncidents(rawCases ? applyStoredCaseStates(built, rawCases) : built);
      })
      .catch(() => {
        // Backend unreachable at mount — leave events empty rather than
        // silently substituting mock data.
      })
      .finally(() => {
        if (!cancelled) setHistoryLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const socket = connectTripwireSocket({
      onConnectionChange: setBackendConnected,
      onEvent: (raw) => {
        const mapped = mapTripwireEvent(raw);
        if (mapped.severity === "Critical") {
          lastCriticalEventRef.current = mapped;
        }
        setEvents((prev) => [mapped, ...prev]);
        setIncidents((prev) => foldEventIntoIncidents(prev, mapped));
        setLastArrivedId(mapped.id);
      },
      onPanic: (raw) => {
        setIncidents((prev) => {
          const next = attachBackendPanic(prev, raw, lastCriticalEventRef.current);
          const crit = lastCriticalEventRef.current;
          if (crit) {
            const updated = next.find((inc) => inc.key === `${crit.process}::${crit.pid}`);
            if (updated) persistCase(updated);
          }
          return next;
        });

        // If panic mode actually killed the process our own "Simulate
        // detection" click launched, the simulation is over — the pipeline
        // itself stopped it, not the Stop button. Reflect that in the UI
        // instead of leaving the button stuck on "running" for a process
        // that's already dead.
        setSimulationPid((prevPid) => {
          if (prevPid != null && raw.killed === prevPid) {
            setSimulationRunning(false);
            return null;
          }
          return prevPid;
        });
      },
      onResponseAck: (raw) => {
        // Source of truth for suspend/kill/lock: confirms what the backend
        // actually did (or skipped, e.g. dry-run/allowlist), separate from
        // the dashboard's own optimistic local status update.
        setLastActionResult((prev) =>
          prev ? { ...prev, backendAck: raw } : { before: "", after: `${raw.action}: ${raw.status}`, backendAck: raw }
        );

        // Resolve the case's pending suspend/kill now that we actually know
        // what happened — only a real "succeeded" + non-dry-run ack earns
        // "Contained". Anything else (skipped_dry_run, skipped_allowlist,
        // failed, or dry-run "succeeded") leaves the case open so the
        // analyst can see it wasn't really handled and try again.
        setIncidents((prev) => {
          const targetPid = String(raw.target);
          let changed = null;

          const next = prev.map((inc) => {
            if (String(inc.pid) !== targetPid || inc.pendingAction !== raw.action) return inc;
            const reallyContained = raw.status === "succeeded" && raw.dry_run === false;
            const updated = {
              ...inc,
              status: reallyContained ? "contained" : "open",
              pendingAction: null,
              actionLog: inc.actionLog.map((entry, i) =>
                i === inc.actionLog.length - 1 && entry.pending
                  ? {
                      ...entry,
                      pending: false,
                      after: reallyContained
                        ? entry.after
                        : `${raw.action}: ${raw.status}${raw.reason ? ` (${raw.reason})` : ""} — process still running`,
                    }
                  : entry
              ),
            };
            changed = updated;
            return updated;
          });

          if (changed) persistCase(changed);
          return next;
        });
      },
    });

    const stopHealthPoll = pollHealth(setHealth);

    return () => {
      socket.disconnect();
      stopHealthPoll();
    };
  }, []);

  // Keep the selection pointed at something sensible: default to the most
  // urgent open case, and never leave the drawer pinned to a case that no
  // longer exists (e.g. after Reset).
  useEffect(() => {
    if (incidents.length === 0) {
      if (selectedIncidentId !== null) setSelectedIncidentId(null);
      return;
    }
    if (!incidents.some((inc) => inc.id === selectedIncidentId)) {
      const openFirst = incidents.find((inc) => inc.status === "open" || inc.status === "escalated");
      setSelectedIncidentId((openFirst || incidents[0]).id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidents]);

  /**
   * "Simulate detection" button. When the backend is reachable, this now
   * launches a REAL simulator.py subprocess (POST /simulate, default mode
   * "persist") that touches actual decoy files — the resulting events flow
   * through the real watcher -> attribution -> classifier -> panic pipeline
   * and arrive over the same tripwire_event/panic_mode websocket as any
   * genuine detection, so Suspend/Kill/auto-escalation all have a real,
   * still-running process to act on instead of a canned demo row.
   *
   * Falls back to the old canned-event injection only when the backend is
   * unreachable, so the dashboard still has *something* to demo offline —
   * that fallback never touches real files or the real pipeline, since
   * there's no backend to run it against.
   */
  const triggerSimulation = () => {
    setSimulationError(null);

    if (!backendConnected) {
      setEvents(suspiciousEvents);
      setIncidents(buildIncidentsFromEvents(suspiciousEvents));
      setLastActionResult(null);
      setLastArrivedId(suspiciousEvents[0]?.id ?? null);
      return;
    }

    fetch(`${BACKEND_URL}/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "persist" }),
    })
      .then((res) => res.json().then((body) => ({ ok: res.ok, body })))
      .then(({ ok, body }) => {
        if (!ok) {
          setSimulationError(body.error || "Failed to start simulation");
          return;
        }
        setSimulationRunning(true);
        setSimulationPid(body.pid);
      })
      .catch(() => setSimulationError("Backend unreachable — could not start simulation"));
  };

  /**
   * Stops a simulator subprocess started by triggerSimulation. Needed
   * because persist mode (the default) runs until something stops it —
   * either this, or panic mode actually suspending/killing it as the
   * detection response plays out.
   */
  const stopSimulation = () => {
    if (simulationPid == null) {
      setSimulationRunning(false);
      return;
    }
    fetch(`${BACKEND_URL}/simulate/${simulationPid}`, { method: "DELETE" })
      .catch(() => {})
      .finally(() => {
        setSimulationRunning(false);
        setSimulationPid(null);
      });
  };

  /**
   * Full reset. Previously this only cleared local React state — the
   * backend's event history and persisted cases were untouched, so on the
   * very next reload (or even without one, once /cases persistence landed)
   * everything "Reset" just cleared came right back. This now wipes the
   * backend's event + case tables too, best-effort, so Reset actually resets.
   */
  const clearSimulation = () => {
    setEvents([]);
    setIncidents([]);
    setSelectedIncidentId(null);
    setLastActionResult(null);
    fetch(`${BACKEND_URL}/events`, { method: "DELETE" }).catch(() => {});
    fetch(`${BACKEND_URL}/cases`, { method: "DELETE" }).catch(() => {});
  };

  /**
   * Runs a response action (suspend / kill / isolate / escalate / dismiss)
   * against one case. Only "suspend" and "kill" have real backend support
   * (PanicController.suspend/kill via POST /action) — "isolate" and
   * "escalate" have no wire-contract endpoint, so they only ever update
   * the case locally (see RESPONSE_ACTIONS' `backendSupported` flag and
   * its "(logged only)" labeling in data/incidents.js).
   */
  const respondToIncident = (incidentId, actionKey) => {
    const dryRun = health?.dry_run !== false;
    const target = incidents.find((inc) => inc.id === incidentId)?.pid;

    setIncidents((prev) => {
      const { incidents: next, result } = respondToIncidentCase(prev, incidentId, actionKey, dryRun);
      if (result) setLastActionResult(result);
      const updated = next.find((inc) => inc.id === incidentId);
      if (updated) persistCase(updated);
      return next;
    });

    if ((actionKey === "suspend" || actionKey === "kill") && target != null && target !== "—") {
      fetch(`${BACKEND_URL}/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: actionKey, target }),
      }).catch(() => {
        // Backend unreachable — the optimistic local update above still
        // stands, but nothing real happened. response_ack (if it arrives)
        // is the source of truth for whether the process was actually
        // touched; this fire-and-forget call is best-effort.
      });
    }
  };

  const addIncidentNote = (incidentId, text) => {
    setIncidents((prev) => {
      const next = addNoteToIncidents(prev, incidentId, text);
      const updated = next.find((inc) => inc.id === incidentId);
      if (updated) persistCase(updated);
      return next;
    });
  };

  /**
   * Removes one case from the queue. Persists a "removed" tombstone rather
   * than physically deleting the case row: incidents are always rebuilt
   * from the raw event log on reload, and the underlying events for this
   * process are still in that log. Without a tombstone to check against,
   * the next rebuild would recreate this exact incident fresh — making
   * deletion look like it silently undid itself on refresh.
   */
  const removeIncident = (incidentId) => {
    setIncidents((prev) => {
      const target = prev.find((inc) => inc.id === incidentId);
      if (target) persistCase({ ...target, status: "removed" });
      return removeIncidentFromList(prev, incidentId);
    });
  };

  /** Bulk-clears every contained/dismissed case (tombstoned, same reasoning as removeIncident), leaving open/escalated work untouched. */
  const clearResolved = () => {
    setIncidents((prev) => {
      const resolved = prev.filter((inc) => inc.status !== "open" && inc.status !== "escalated");
      resolved.forEach((inc) => persistCase({ ...inc, status: "removed" }));
      return clearResolvedIncidents(prev);
    });
  };

  /** Removes a single row from the activity feed — e.g. a noisy/irrelevant event an analyst wants gone. */
  const removeEvent = (eventId) => {
    setEvents((prev) => prev.filter((e) => e.id !== eventId));
    deleteEventFromBackend(eventId);
  };

  /** Clears every row from the activity feed without touching incidents/cases — a lighter-weight option than the full Reset. */
  const clearAllEvents = () => {
    setEvents([]);
    clearAllEventsFromBackend();
  };

  /** Live-updates warning/critical thresholds on the backend (best-effort). */
  const applyThresholds = async (next) => {
    setThresholdsState(next); // optimistic — sliders should feel instant
    setThresholdUpdateError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/config/thresholds`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(next),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setThresholdUpdateError(body.error || "Backend rejected the new thresholds.");
      }
    } catch {
      setThresholdUpdateError("Backend unreachable — thresholds apply locally only.");
    }
  };

  /**
   * Live-updates the per-severity auto-response rules and/or the
   * escalate-to-kill-after-N-touches threshold (POST /config/auto-response).
   * Accepts a partial patch — either key alone is fine, matching the
   * backend's own "either or both" contract — and always sends the full
   * current rules object merged with the patch, since the backend replaces
   * whichever severities are present in the body rather than deep-merging
   * per-action.
   */
  const applyAutoResponse = async (patch) => {
    const nextRules = patch.rules ? { ...autoResponseRules, ...patch.rules } : autoResponseRules;
    const nextEscalate =
      typeof patch.escalate_to_kill_after_touches === "number"
        ? patch.escalate_to_kill_after_touches
        : escalateAfterTouches;

    // Optimistic — the panel should feel instant, same as thresholds.
    setAutoResponseRulesState(nextRules);
    setEscalateAfterTouchesState(nextEscalate);
    setAutoResponseUpdateError(null);
    setAutoResponsePending(true);
    try {
      const res = await fetch(`${BACKEND_URL}/config/auto-response`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules: nextRules, escalate_to_kill_after_touches: nextEscalate }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setAutoResponseUpdateError(body.error || "Backend rejected the new auto-response rules.");
      } else {
        // Reconcile with whatever the backend actually stored, in case it
        // normalized/rejected part of the patch.
        if (body.rules) setAutoResponseRulesState(body.rules);
        if (typeof body.escalate_to_kill_after_touches === "number") {
          setEscalateAfterTouchesState(body.escalate_to_kill_after_touches);
        }
      }
    } catch {
      setAutoResponseUpdateError("Backend unreachable — rules apply locally only.");
    } finally {
      setAutoResponsePending(false);
    }
  };

  /** Arms/disarms panic dry-run. Requires confirm=true when going live. */
  const setDryRun = async (dryRun, confirm = false) => {
    setDryRunPending(true);
    try {
      const res = await fetch(`${BACKEND_URL}/config/dry-run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dry_run: dryRun, confirm }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok) {
        setHealth((prev) => (prev ? { ...prev, dry_run: body.dry_run } : prev));
      }
      return body;
    } catch {
      return { error: "Backend unreachable." };
    } finally {
      setDryRunPending(false);
    }
  };

  return {
    events,
    incidents,
    selectedIncidentId,
    selectIncident: setSelectedIncidentId,
    backendConnected,
    health,
    historyLoaded,
    thresholds,
    thresholdUpdateError,
    autoResponseRules,
    escalateAfterTouches,
    autoResponseUpdateError,
    autoResponsePending,
    applyAutoResponse,
    dryRunPending,
    lastArrivedId,
    lastActionResult,
    triggerSimulation,
    stopSimulation,
    simulationRunning,
    simulationError,
    clearSimulation,
    respondToIncident,
    addIncidentNote,
    removeIncident,
    clearResolved,
    removeEvent,
    clearAllEvents,
    applyThresholds,
    setDryRun,
  };
}
