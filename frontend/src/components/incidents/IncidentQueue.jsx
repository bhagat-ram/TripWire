import { Flame, AlertTriangle, Ban, ShieldOff, ArrowUpRight, X, Trash2, ShieldCheck, UserCog, Zap } from "lucide-react";
import { sortIncidents } from "../../data/incidents";

const MITIGATION_META = {
  auto_mitigated: { label: "Auto-mitigated", icon: ShieldCheck, className: "mitigation-auto" },
  requires_manual: { label: "Requires manual action", icon: UserCog, className: "mitigation-manual" },
};

const STATUS_META = {
  open: { label: "Open", icon: AlertTriangle, className: "case-status-open" },
  escalated: { label: "Escalated", icon: ArrowUpRight, className: "case-status-escalated" },
  contained: { label: "Contained", icon: Ban, className: "case-status-contained" },
  dismissed: { label: "Dismissed", icon: ShieldOff, className: "case-status-dismissed" },
};

const CLOSED_STATUSES = new Set(["contained", "dismissed"]);

/**
 * The triage queue: every distinct suspicious process gets its own row here,
 * independent of whatever the backend's single panic_mode slot last said.
 * This is what makes "choosing which incident to work" possible — before,
 * there was only ever one incident to look at.
 *
 * Cases never disappear on their own — a resolved case stays in the queue
 * until an analyst explicitly clears it, either one at a time (the X on a
 * closed card) or in bulk ("Clear resolved"). Open/escalated cases can't be
 * bulk-cleared, so active work is never silently lost.
 */
export function IncidentQueue({ incidents, selectedIncidentId, onSelect, onRemove, onClearResolved }) {
  const ordered = sortIncidents(incidents);
  const openCount = incidents.filter((i) => i.status === "open" || i.status === "escalated").length;
  const resolvedCount = incidents.filter((i) => CLOSED_STATUSES.has(i.status)).length;

  return (
    <section className="incident-queue-section">
      <div className="section-heading">
        <div>
          <h2>Incident queue</h2>
          <p>
            {incidents.length === 0
              ? "No cases open — cases are created automatically from Warning/Critical activity."
              : `${openCount} of ${incidents.length} case${incidents.length === 1 ? "" : "s"} need attention.`}
          </p>
        </div>

        {resolvedCount > 0 && (
          <button
            className="filter-button"
            onClick={onClearResolved}
            title={`Remove ${resolvedCount} contained/dismissed case${resolvedCount === 1 ? "" : "s"} from the queue`}
          >
            <Trash2 size={12} />
            Clear resolved ({resolvedCount})
          </button>
        )}
      </div>

      {incidents.length === 0 ? (
        <div className="incident-queue-empty">
          <Flame size={16} />
          <span>Nothing to triage right now.</span>
        </div>
      ) : (
        <div className="incident-queue-list">
          {ordered.map((incident) => {
            const meta = STATUS_META[incident.status] || STATUS_META.open;
            const StatusIcon = meta.icon;
            const isSelected = incident.id === selectedIncidentId;
            const isCritical = incident.severity === "Critical";
            const isClosed = CLOSED_STATUSES.has(incident.status);

            return (
              <div key={incident.id} className={`incident-card-wrap ${isClosed ? "removable" : ""}`}>
                <button
                  className={`incident-card ${isSelected ? "selected" : ""} ${meta.className}`}
                  onClick={() => onSelect(incident.id)}
                >
                  <div className={`incident-card-severity ${isCritical ? "critical" : "warning"}`}>
                    {isCritical ? <Flame size={14} /> : <AlertTriangle size={14} />}
                  </div>

                  <div className="incident-card-body">
                    <div className="incident-card-title">
                      <strong>{incident.process}</strong>
                      <span className="incident-card-pid">PID {incident.pid}</span>
                    </div>
                    <div className="incident-card-meta">
                      {incident.eventIds.length} evidence event{incident.eventIds.length === 1 ? "" : "s"} ·
                      last seen {incident.lastSeen}
                      {incident.mitre ? ` · ${incident.mitre}` : ""}
                    </div>
                    {incident.backendDriven && incident.mitigationStatus && (
                      <div className={`incident-card-mitigation ${MITIGATION_META[incident.mitigationStatus]?.className || ""}`}>
                        {(() => {
                          const MitigationIcon = MITIGATION_META[incident.mitigationStatus]?.icon || UserCog;
                          return <MitigationIcon size={11} />;
                        })()}
                        {MITIGATION_META[incident.mitigationStatus]?.label || "Unknown"}
                        {incident.escalated && (
                          <span className="incident-card-escalated-tag" title="Auto-escalated to kill after repeat post-suspend activity">
                            <Zap size={10} /> escalated
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="incident-card-status">
                    <StatusIcon size={12} />
                    {meta.label}
                  </div>
                </button>

                {isClosed && (
                  <button
                    className="incident-card-remove"
                    onClick={(e) => {
                      e.stopPropagation();
                      onRemove(incident.id);
                    }}
                    title="Remove this case from the queue"
                    aria-label="Remove case"
                  >
                    <X size={11} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
