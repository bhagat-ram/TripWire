import { useEffect, useState } from "react";
import { AlertTriangle, Ban, Check, ArrowUpRight, ShieldOff } from "lucide-react";

const STATUS_COPY = {
  open: { title: (i) => i.title, icon: AlertTriangle, statusClass: "status-check-danger" },
  escalated: {
    title: (i) => `${i.title} — escalated`,
    icon: ArrowUpRight,
    statusClass: "status-check-danger",
  },
  contained: { title: () => "Incident contained", icon: Ban, statusClass: "" },
  dismissed: { title: () => "Marked as false positive", icon: ShieldOff, statusClass: "" },
};

export function DetectionPanel({ incident, events, thresholds, thresholdUpdateError, onApplyThresholds }) {
  const active = incident && (incident.status === "open" || incident.status === "escalated");

  const [local, setLocal] = useState(thresholds);

  useEffect(() => setLocal(thresholds), [thresholds]);

  const commit = (next) => {
    // Keep critical strictly above warning so the pair always stays valid.
    const safe = { warning: next.warning, critical: Math.max(next.critical, next.warning + 1) };
    setLocal(safe);
    onApplyThresholds(safe);
  };

  const touchCounts = events.map((e) => e.touchCount).filter((n) => typeof n === "number");
  const wouldWarn = touchCounts.filter((n) => n >= local.warning && n < local.critical).length;
  const wouldEscalate = touchCounts.filter((n) => n >= local.critical).length;

  const copy = incident ? STATUS_COPY[incident.status] || STATUS_COPY.open : null;
  const StatusIcon = copy?.icon || Check;

  return (
    <section className="detection-section">
      <div className="section-heading">
        <div>
          <h2>Detection</h2>
          <p>Detection and attribution status for the selected case.</p>
        </div>
      </div>

      <div className={`detection-card ${active ? "detection-active" : ""}`}>
        <div className="detection-status">
          <div className={`status-check ${active ? "status-check-danger" : ""}`}>
            <StatusIcon size={17} />
          </div>

          <div>
            <div className="detection-title">
              {incident ? copy.title(incident) : "No case selected"}
            </div>

            <div className="detection-description">
              {incident
                ? incident.description
                : "Select a case from the incident queue to see detection details, or wait for new activity."}
            </div>
          </div>
        </div>

        <div className="detection-fields">
          <div className="field">
            <span>Process</span>
            <strong>{incident?.process || "—"}</strong>
          </div>

          <div className="field">
            <span>PID</span>
            <strong>{incident?.pid || "—"}</strong>
          </div>

          <div className="field">
            <span>Severity</span>
            <strong className={active ? "critical-text" : ""}>{incident?.severity || "—"}</strong>
          </div>

          <div className="field">
            <span>MITRE ATT&CK</span>
            <strong>{incident?.mitre || "—"}</strong>
          </div>
        </div>
      </div>

      <div className="threshold-panel">
        <div className="threshold-panel-title">
          Touch thresholds
          <span>Fires warning / critical after N touches within the detection window</span>
        </div>

        <div className="slider-row">
          <label>Warning</label>
          <input
            type="range"
            min="1"
            max="15"
            value={local.warning}
            onChange={(e) => setLocal({ ...local, warning: Number(e.target.value) })}
            onMouseUp={(e) => commit({ ...local, warning: Number(e.target.value) })}
            onTouchEnd={(e) => commit({ ...local, warning: Number(e.target.value) })}
            onKeyUp={(e) => commit({ ...local, warning: Number(e.target.value) })}
          />
          <output>{local.warning}</output>
        </div>

        <div className="slider-row critical">
          <label>Critical</label>
          <input
            type="range"
            min="2"
            max="20"
            value={local.critical}
            onChange={(e) => setLocal({ ...local, critical: Number(e.target.value) })}
            onMouseUp={(e) => commit({ ...local, critical: Number(e.target.value) })}
            onTouchEnd={(e) => commit({ ...local, critical: Number(e.target.value) })}
            onKeyUp={(e) => commit({ ...local, critical: Number(e.target.value) })}
          />
          <output>{local.critical}</output>
        </div>

        <div className="threshold-preview">
          <span>
            With these thresholds, past events would show <strong>{wouldWarn}</strong> warning
            and <strong>{wouldEscalate}</strong> critical.
          </span>
        </div>

        {thresholdUpdateError && <div className="threshold-error">{thresholdUpdateError}</div>}
      </div>
    </section>
  );
}
