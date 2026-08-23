/**
 * tripwireSocket.js
 *
 * Thin wrapper around socket.io-client that speaks the backend's frozen
 * frontend integration contract (see build plan Section 6):
 *
 *   WebSocket "tripwire_event": { event_type, file_path, pid, process_name,
 *     attribution_confidence, parent_pid, parent_name, severity, mitre_id,
 *     timestamp }
 *   WebSocket "panic_mode": { suspended: [pid,...], killed: pid|null, dry_run }
 *   REST GET /health: { watcher_alive, last_event_ts, dead_letter_count }
 *
 * Do not rename these event names or field keys without updating both
 * sides — the backend build plan calls this contract frozen.
 */

import { io } from "socket.io-client";

export const BACKEND_URL =
  import.meta.env.VITE_TRIPWIRE_BACKEND_URL || "http://127.0.0.1:5050";

/**
 * Connects to the backend and wires up the two event types.
 * Returns the raw socket so the caller can disconnect() on unmount.
 *
 * @param {Object} handlers
 * @param {(event: object) => void} handlers.onEvent - raw tripwire_event payload
 * @param {(panic: object) => void} handlers.onPanic - raw panic_mode payload
 * @param {(ack: object) => void} [handlers.onResponseAck] - raw response_ack
 *   payload, emitted by the backend after a POST /action (suspend/kill/lock)
 *   actually runs — the source of truth for whether something real happened,
 *   as opposed to the dashboard's own optimistic local status update.
 * @param {(connected: boolean) => void} [handlers.onConnectionChange]
 */
export function connectTripwireSocket({ onEvent, onPanic, onResponseAck, onConnectionChange }) {
  const socket = io(BACKEND_URL, {
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
  });

  socket.on("connect", () => onConnectionChange?.(true));
  socket.on("disconnect", () => onConnectionChange?.(false));
  socket.on("connect_error", () => onConnectionChange?.(false));

  socket.on("tripwire_event", (payload) => onEvent?.(payload));
  socket.on("panic_mode", (payload) => onPanic?.(payload));
  socket.on("response_ack", (payload) => onResponseAck?.(payload));

  return socket;
}

/** Polls GET /health on an interval. Returns a cleanup function. */
export function pollHealth(onHealth, intervalMs = 5000) {
  let stopped = false;

  const tick = async () => {
    if (stopped) return;
    try {
      const res = await fetch(`${BACKEND_URL}/health`);
      if (res.ok) onHealth?.(await res.json());
    } catch {
      // backend unreachable — connection state is already surfaced via the socket
    }
  };

  tick();
  const id = setInterval(tick, intervalMs);
  return () => {
    stopped = true;
    clearInterval(id);
  };
}

// ─── mapping: backend wire contract -> dashboard's display shape ──────────

const EVENT_TYPE_LABELS = {
  read: "Read",
  modify: "Modify",
  rename: "Rename",
  delete: "Delete",
};

const SEVERITY_LABELS = {
  critical: "Critical",
  warning: "Warning",
  info: "Normal",
};

let _nextClientId = 1;

/** Maps a raw tripwire_event payload to the shape App.jsx renders. */
export function mapTripwireEvent(raw) {
  const ts = raw.timestamp ? new Date(raw.timestamp * 1000) : new Date();
  return {
    // The backend's real row id (now included on the wire) — used to
    // delete this specific event later. Falls back to a client-generated
    // id only for the rare payload that somehow omits it, so rendering
    // (React `key`, isNew/isSelected matching) never breaks.
    id: raw.id ?? `${ts.getTime()}-${_nextClientId++}`,
    type: EVENT_TYPE_LABELS[raw.event_type] || raw.event_type,
    resource: raw.file_path,
    filename: raw.filename || raw.file_path?.split(/[\\/]/).pop(),
    process: raw.process_name || "unknown",
    pid: raw.pid ?? "—",
    parentProcess: raw.parent_name || null,
    parentPid: raw.parent_pid ?? null,
    time: ts.toLocaleTimeString(),
    receivedAt: Date.now(),
    severity: SEVERITY_LABELS[raw.severity] || "Normal",
    severityRaw: raw.severity || "info",
    mitre: raw.mitre_id || null,
    attributionConfidence: raw.attribution_confidence || "unknown",
    touchCount: raw.touch_count ?? null,
    recommendedAction: raw.recommended_action || null,
    placementLabel: raw.placement_label || null,
  };
}

// Note: panic_mode payloads carry no process/PID context of their own —
// attribution lives on the event that triggered it. Folding a panic_mode
// payload onto the right case (by matching that last-critical event's
// process+PID) is handled by data/incidents.js's attachBackendPanic, since
// it needs to find the matching case in the incident list, not just build
// one standalone object.
