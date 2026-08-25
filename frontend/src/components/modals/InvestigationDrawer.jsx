import { useState } from "react";
import {
  AlertTriangle,
  FileText,
  Ban,
  Skull,
  WifiOff,
  ArrowUpRight,
  ShieldOff,
  Check,
  Info,
  Send,
} from "lucide-react";
import { MitreCard } from "../threat/MitreCard";
import { previewForFilename } from "../../data/previewContent";

const STATUS_BADGE = {
  open: { label: "Open", className: "" },
  escalated: { label: "Escalated", className: "critical-text" },
  contained: { label: "Contained", className: "" },
  dismissed: { label: "Dismissed", className: "" },
};

/**
 * The drawer is now a full case view: it shows every piece of evidence tied
 * to the incident (not just the one row that was clicked), the analyst's
 * running notes, the action history, and every response option — not a
 * single "Contain incident" button. `focusEvent` is whichever row the
 * analyst actually clicked, so its details stay front and center, but the
 * rest of the case's evidence is right below it for full context.
 */
export function InvestigationDrawer({ incident, focusEvent, allEvents, onClose, onRespond, onAddNote }) {
  const [note, setNote] = useState("");

  if (!incident) return null;

  const evidence = allEvents.filter((e) => incident.eventIds.includes(e.id));
  const event = focusEvent && incident.eventIds.includes(focusEvent.id) ? focusEvent : evidence[0];
  const isCritical = incident.severity === "Critical";
  const isOpenCase = incident.status === "open" || incident.status === "escalated";
  const isPending = Boolean(incident.pendingAction);
  const badge = STATUS_BADGE[incident.status] || STATUS_BADGE.open;

  const submitNote = () => {
    if (!note.trim()) return;
    onAddNote(incident.id, note);
    setNote("");
  };

  return (
    <aside className="investigation-drawer">
      <div className="drawer-header">
        <div>
          <span className="drawer-eyebrow">Case · {incident.id}</span>
          <h2>{incident.process}</h2>
        </div>

        <button className="drawer-close" onClick={onClose}>
          ×
        </button>
      </div>

      <div className="drawer-body">
        <div className={`drawer-alert ${!isCritical ? "info" : ""}`}>
          <div className="drawer-alert-icon">
            {isOpenCase ? <AlertTriangle size={15} /> : <Info size={15} />}
          </div>
          <div>
            <strong>
              {incident.title} <span className={`case-badge ${badge.className}`}>{badge.label}</span>
            </strong>
            <span>{incident.description}</span>
          </div>
        </div>

        <div className="drawer-section">
          <div className="drawer-section-title">Evidence timeline ({evidence.length})</div>
          <div className="evidence-timeline">
            {evidence.map((e) => (
              <div key={e.id} className={`evidence-row ${e.id === event?.id ? "focused" : ""}`}>
                <span className="evidence-time">{e.time}</span>
                <span className="evidence-type">{e.type}</span>
                <span className="evidence-resource">{e.resource}</span>
                <span className={`evidence-severity ${e.severity === "Critical" ? "critical-text" : ""}`}>
                  {e.severity}
                </span>
              </div>
            ))}
          </div>
        </div>

        {event && (
          <div className="drawer-section">
            <div className="drawer-section-title">Focused resource</div>
            <div className="drawer-resource">
              <FileText size={15} />
              <span>{event.resource}</span>
            </div>
            <span className="drawer-preview-label">Decoy content preview — not a live read</span>
            <div className="drawer-preview">{previewForFilename(event.filename)}</div>
          </div>
        )}

        <div className="drawer-section">
          <div className="drawer-section-title">Attributed process tree</div>
          <div className="process-tree">
            {incident.parentProcess && (
              <>
                <div className="process-tree-node">
                  {incident.parentProcess}
                  <span className="pid-tag">PID {incident.parentPid ?? "—"}</span>
                </div>
                <div className="process-tree-connector">└─</div>
              </>
            )}
            <div className="process-tree-node child">
              {incident.process}
              <span className="pid-tag">PID {incident.pid}</span>
            </div>
          </div>
        </div>

        {(isCritical || incident.severity === "Warning") && (
          <div className="drawer-section">
            <div className="drawer-section-title">MITRE ATT&CK</div>
            <MitreCard mitreId={incident.mitre} event={event} />
          </div>
        )}

        <div className="drawer-section">
          <div className="drawer-section-title">Analyst notes</div>
          <div className="notes-list">
            {incident.notes.length === 0 && <div className="notes-empty">No notes yet.</div>}
            {incident.notes.map((n) => (
              <div key={n.id} className="note-row">
                <span className="note-ts">{n.ts}</span>
                <span>{n.text}</span>
              </div>
            ))}
          </div>
          <div className="note-composer">
            <input
              type="text"
              value={note}
              placeholder="Add a finding or next step…"
              onChange={(e) => setNote(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submitNote()}
            />
            <button onClick={submitNote} disabled={!note.trim()}>
              <Send size={13} />
            </button>
          </div>
        </div>

        {incident.actionLog.length > 0 && (
          <div className="drawer-section">
            <div className="drawer-section-title">Action history</div>
            <div className="action-history">
              {incident.actionLog.map((a) => (
                <div key={a.id} className={`action-history-row ${a.pending ? "pending" : ""}`}>
                  <span className="action-history-ts">{a.ts}</span>
                  <strong>{a.label}</strong>
                  <span className="action-history-transition">
                    {a.before} → {a.after}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {isOpenCase && (
          <div className="drawer-section">
            <div className="drawer-section-title">Respond to this case</div>
            <div className="drawer-response-grid">
              <button
                className="drawer-action-btn"
                disabled={isPending}
                onClick={() => onRespond(incident.id, "suspend")}
              >
                <Ban size={13} />
                {incident.pendingAction === "suspend" ? "Suspending…" : "Suspend process"}
              </button>
              <button
                className="drawer-action-btn"
                disabled={isPending}
                onClick={() => onRespond(incident.id, "kill")}
              >
                <Skull size={13} />
                {incident.pendingAction === "kill" ? "Killing…" : "Kill process"}
              </button>
              <button className="drawer-action-btn" onClick={() => onRespond(incident.id, "isolate")}>
                <WifiOff size={13} />
                Isolate host
              </button>
              <button className="drawer-action-btn" onClick={() => onRespond(incident.id, "escalate")}>
                <ArrowUpRight size={13} />
                Escalate to SOC
              </button>
              <button
                className="drawer-action-btn dismiss"
                onClick={() => onRespond(incident.id, "dismiss")}
              >
                <ShieldOff size={13} />
                Dismiss as false positive
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="drawer-footer">
        {isOpenCase ? (
          <span className="drawer-footer-hint">Choose a response action above.</span>
        ) : (
          <div className="drawer-contained">
            <Check size={13} />
            {incident.status === "dismissed" ? "Dismissed as false positive" : "Case contained"}
          </div>
        )}
      </div>
    </aside>
  );
}
