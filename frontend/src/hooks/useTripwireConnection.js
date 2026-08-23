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

function deleteCaseFromBackend(incidentId) {
  fetch(`${BACKEND_URL}/cases/${encodeURIComponent(incidentId)}`, { method: "DELETE" }).catch(() => {});
}

function deleteEventFromBackend(eventId) {
  fetch(`${BACKEND_URL}/events/${encodeURIComponent(eventId)}`, { method: "DELETE" }).catch(() => {});
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
  const [dryRunPending, setDryRunPending] = useState(false);
  const [lastArrivedId, setLastArrivedId] = useState(null);
  const [lastActionResult, setLastActionResult] = useState(null);
  const [historyLoaded, setHistoryLoaded] = useState(false);

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
    ])
      .then(([rawEvents, rawCases]) => {
        if (cancelled || !rawEvents) return;
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
      },
      onResponseAck: (raw) => {
        // Source of truth for suspend/kill/lock: confirms what the backend
        // actually did (or skipped, e.g. dry-run/allowlist), separate from
        // the dashboard's own optimistic local status update.
        setLastActionResult((prev) =>
          prev ? { ...prev, backendAck: raw } : { before: "", after: `${raw.action}: ${raw.status}`, backendAck: raw }
        );
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

  const triggerSimulation = () => {
    setEvents(suspiciousEvents);
    setIncidents(buildIncidentsFromEvents(suspiciousEvents));
    setLastActionResult(null);
    setLastArrivedId(suspiciousEvents[0]?.id ?? null);
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

  /** Removes one case from the queue — for clearing out an old/resolved incident individually. */
  const removeIncident = (incidentId) => {
    setIncidents((prev) => removeIncidentFromList(prev, incidentId));
    deleteCaseFromBackend(incidentId);
  };

  /** Bulk-clears every contained/dismissed case, leaving open/escalated work untouched. */
  const clearResolved = () => {
    setIncidents((prev) => {
      const resolvedIds = prev
        .filter((inc) => inc.status !== "open" && inc.status !== "escalated")
        .map((inc) => inc.id);
      resolvedIds.forEach(deleteCaseFromBackend);
      return clearResolvedIncidents(prev);
    });
  };

  /** Removes a single row from the activity feed — e.g. a noisy/irrelevant event an analyst wants gone. */
  const removeEvent = (eventId) => {
    setEvents((prev) => prev.filter((e) => e.id !== eventId));
    deleteEventFromBackend(eventId);
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
    dryRunPending,
    lastArrivedId,
    lastActionResult,
    triggerSimulation,
    clearSimulation,
    respondToIncident,
    addIncidentNote,
    removeIncident,
    clearResolved,
    removeEvent,
    applyThresholds,
    setDryRun,
  };
}
