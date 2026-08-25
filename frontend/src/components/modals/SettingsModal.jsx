import { X } from "lucide-react";

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
 * Settings modal for the two backend knobs that previously had no UI at
 * all: per-severity auto-response actions (POST /config/auto-response) and
 * the auto-escalate-to-kill touch count. Touch thresholds (warning/critical)
 * already have a home in DetectionPanel's threshold-panel, so this modal
 * doesn't duplicate them — it's reachable from the same gear icon for
 * discoverability, but stays scoped to auto-response.
 */
export function SettingsModal({
  open,
  onClose,
  rules,
  escalateAfterTouches,
  onApply,
  updateError,
  pending,
}) {
  if (!open) return null;

  const toggleAction = (severity, action) => {
    const current = rules[severity] || [];
    const has = current.includes(action);
    // Unchecking every action for a severity should fall back to
    // "monitor" (alert-only) rather than an empty list — an empty list
    // reads the same as monitor-only to the backend, but sending "monitor"
    // explicitly keeps the stored rule self-documenting.
    const nextActions = has ? current.filter((a) => a !== action) : [...current.filter((a) => a !== "monitor"), action];
    onApply({ rules: { [severity]: nextActions.length ? nextActions : ["monitor"] } });
  };

  const isMonitorOnly = (severity) => {
    const actions = rules[severity] || [];
    return actions.length === 0 || (actions.length === 1 && actions[0] === "monitor");
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
        <div className="settings-modal-header">
          <h3>Automated response rules</h3>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>

        <p className="settings-modal-intro">
          Choose which actions fire automatically the moment a case reaches
          each severity — no analyst click required. Leave a severity
          unchecked to alert only (monitor).
        </p>

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
                      disabled={pending}
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
              disabled={pending}
              onChange={(e) => {
                const n = Number(e.target.value);
                if (Number.isInteger(n) && n >= 1) {
                  onApply({ escalate_to_kill_after_touches: n });
                }
              }}
            />
            <span>touches</span>
          </div>
        </div>

        {updateError && <div className="threshold-error">{updateError}</div>}

        <div className="dryrun-modal-actions">
          <button className="primary-button" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
