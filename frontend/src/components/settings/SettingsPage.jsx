import { useEffect, useState } from "react";
import { ShieldAlert, SlidersHorizontal, Radar } from "lucide-react";

// Order controls both display order and the order badges render in.
const SEVERITIES = [
  { key: "info", label: "Info", hint: "Every logged touch, before any threshold is crossed." },
  { key: "warning", label: "Warning", hint: "Touch count has crossed the warning threshold." },
  { key: "critical", label: "Critical", hint: "Touch count has crossed the critical threshold." },
];

// "monitor" is intentionally not a checkbox — it's not a real action (it's
// what happens when NO action is checked: alert-only, nothing sent to
// PanicController). Offering it as a togglable box next to real actions
// would suggest it stacks with them, which the backend explicitly says it
// doesn't ("combining it with others is redundant but harmless").
const ACTIONS = [
  { key: "suspend", label: "Suspend", hint: "SIGSTOP — pauses the process, reversible." },
  { key: "kill", label: "Kill", hint: "Terminates the process for real." },
  { key: "lock", label: "Lock", hint: "Locks down the real_data directory." },
];

/**
 * Settings — routed page (SidebarNav's SECTIONS: `type: "page"`), replacing
 * both the old gear-icon modal (SettingsModal) *and* the four duplicate
 * dashboard-mirror pages (Analysis/Incidents/Detection/Response) that used
 * to fill this slot. Everything that was previously scattered across a
 * modal (automation rules), DetectionPanel (touch thresholds), and the
 * Topbar (dry-run arming) now lives in one place.
 */
export function SettingsPage({
  rules,
  escalateAfterTouches,
  onApplyAutoResponse,
  autoResponseUpdateError,
  autoResponsePending,
  thresholds,
  thresholdUpdateError,
  onApplyThresholds,
  dryRun,
  dryRunPending,
  onSetDryRun,
}) {
  const [localThresholds, setLocalThresholds] = useState(thresholds);
  const [confirmOpen, setConfirmOpen] = useState(false);

  useEffect(() => setLocalThresholds(thresholds), [thresholds]);

  const commitThresholds = (next) => onApplyThresholds(next);

  const toggleAction = (severity, action) => {
    const current = rules[severity] || [];
    const has = current.includes(action);
    // Unchecking every action for a severity should fall back to
    // "monitor" (alert-only) rather than an empty list — an empty list
    // reads the same as monitor-only to the backend, but sending "monitor"
    // explicitly keeps the stored rule self-documenting.
    const nextActions = has
      ? current.filter((a) => a !== action)
      : [...current.filter((a) => a !== "monitor"), action];
    onApplyAutoResponse({ rules: { [severity]: nextActions.length ? nextActions : ["monitor"] } });
  };

  const isMonitorOnly = (severity) => {
    const actions = rules[severity] || [];
    return actions.length === 0 || (actions.length === 1 && actions[0] === "monitor");
  };

  const handleArm = async () => {
    if (dryRun) {
      setConfirmOpen(true);
    } else {
      await onSetDryRun(true); // disarm back to dry-run needs no confirmation
    }
  };

  const confirmArm = async () => {
    await onSetDryRun(false, true);
    setConfirmOpen(false);
  };

  return (
    <div className="page-view">
      <div className="page-header">
        <div>
          <h1>Settings</h1>
          <p>Detection thresholds, automated response rules, and panic mode — all in one place.</p>
        </div>
      </div>

      {/* Panic mode arm/disarm */}
      <div className="threshold-panel">
        <div className="threshold-panel-title">
          <ShieldAlert size={13} />
          Panic mode
          <span>Dry-run logs actions only; live mode actually suspends, kills, or locks.</span>
        </div>

        <div className="settings-escalate-row">
          <div>
            <label>Current mode</label>
            <span>
              {dryRun
                ? "Panic actions are logged only — nothing touches the real system."
                : "Live — critical detections trigger real process suspension and kill actions."}
            </span>
          </div>
          <div className="settings-escalate-input">
            <button
              className={`dryrun-pill ${dryRun ? "" : "live"}`}
              onClick={handleArm}
              disabled={dryRunPending}
              title={dryRun ? "Click to arm live mode" : "Click to return to dry-run"}
            >
              <ShieldAlert size={11} />
              {dryRun ? "Dry-run" : "Live"}
            </button>
          </div>
        </div>
      </div>

      {/* Touch thresholds */}
      <div className="threshold-panel">
        <div className="threshold-panel-title">
          <Radar size={13} />
          Touch thresholds
          <span>Fires warning / critical after N touches within the detection window</span>
        </div>

        <div className="slider-row">
          <label>Warning</label>
          <input
            type="range"
            min="1"
            max="15"
            value={localThresholds.warning}
            onChange={(e) => setLocalThresholds({ ...localThresholds, warning: Number(e.target.value) })}
            onMouseUp={(e) => commitThresholds({ ...localThresholds, warning: Number(e.target.value) })}
            onTouchEnd={(e) => commitThresholds({ ...localThresholds, warning: Number(e.target.value) })}
            onKeyUp={(e) => commitThresholds({ ...localThresholds, warning: Number(e.target.value) })}
          />
          <output>{localThresholds.warning}</output>
        </div>

        <div className="slider-row critical">
          <label>Critical</label>
          <input
            type="range"
            min="2"
            max="20"
            value={localThresholds.critical}
            onChange={(e) => setLocalThresholds({ ...localThresholds, critical: Number(e.target.value) })}
            onMouseUp={(e) => commitThresholds({ ...localThresholds, critical: Number(e.target.value) })}
            onTouchEnd={(e) => commitThresholds({ ...localThresholds, critical: Number(e.target.value) })}
            onKeyUp={(e) => commitThresholds({ ...localThresholds, critical: Number(e.target.value) })}
          />
          <output>{localThresholds.critical}</output>
        </div>

        {thresholdUpdateError && <div className="threshold-error">{thresholdUpdateError}</div>}
      </div>

      {/* Automated response rules */}
      <div className="threshold-panel">
        <div className="threshold-panel-title">
          <SlidersHorizontal size={13} />
          Automated response rules
          <span>Choose which actions fire automatically at each severity — no analyst click required.</span>
        </div>

        <div className="settings-rules-table">
          {SEVERITIES.map((sev) => (
            <div className="settings-rule-row" key={sev.key}>
              <div className="settings-rule-severity">
                <strong className={sev.key === "critical" ? "critical-text" : ""}>{sev.label}</strong>
                <span>{sev.hint}</span>
              </div>

              <div className="settings-rule-actions">
                {ACTIONS.map((a) => (
                  <label className="settings-action-checkbox" key={a.key} title={a.hint}>
                    <input
                      type="checkbox"
                      checked={(rules[sev.key] || []).includes(a.key)}
                      onChange={() => toggleAction(sev.key, a.key)}
                      disabled={autoResponsePending}
                    />
                    {a.label}
                  </label>
                ))}

                {isMonitorOnly(sev.key) && <span className="settings-monitor-flag">Monitor only</span>}
              </div>
            </div>
          ))}
        </div>

        <div className="settings-escalate-row">
          <div>
            <label htmlFor="escalate-input">Auto-escalate to kill after</label>
            <span>
              If a suspended process keeps generating touches instead of stopping, kill it
              automatically after this many additional touches.
            </span>
          </div>
          <div className="settings-escalate-input">
            <input
              id="escalate-input"
              type="number"
              min="1"
              value={escalateAfterTouches}
              disabled={autoResponsePending}
              onChange={(e) => {
                const n = Number(e.target.value);
                if (Number.isInteger(n) && n >= 1) {
                  onApplyAutoResponse({ escalate_to_kill_after_touches: n });
                }
              }}
            />
            <span>touches</span>
          </div>
        </div>

        {autoResponseUpdateError && <div className="threshold-error">{autoResponseUpdateError}</div>}
      </div>

      {confirmOpen && (
        <div className="modal-overlay" onClick={() => setConfirmOpen(false)}>
          <div className="dryrun-modal" onClick={(e) => e.stopPropagation()}>
            <h3>Arm live panic mode?</h3>
            <p>
              This switches Panic Mode from logged-only to real process
              suspension and kill actions. Every future critical detection
              will act on the live system until you disarm it.
            </p>
            <div className="dryrun-modal-actions">
              <button className="secondary-button" onClick={() => setConfirmOpen(false)}>
                Cancel
              </button>
              <button className="primary-button" onClick={confirmArm}>
                Arm live mode
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
