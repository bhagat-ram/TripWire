import { useState } from "react";
import { Settings, ShieldAlert } from "lucide-react";

const POSTURE_COPY = {
  safe: "Safe",
  watching: "Watching",
  warning: "Warning",
  critical: "Critical",
};

// A quiet flat line at rest; sharper, faster spikes as posture escalates.
// Purely decorative signal — not a real telemetry chart.
const WAVEFORM_PATHS = {
  safe: "M0,10 L20,10 L24,10 L28,10 L48,10 L52,10 L56,10 L100,10",
  watching: "M0,10 L18,10 L22,7 L26,13 L30,10 L60,10 L64,8 L68,12 L72,10 L100,10",
  warning:
    "M0,10 L14,10 L18,4 L22,16 L26,6 L30,10 L50,10 L54,3 L58,17 L62,5 L66,10 L100,10",
  critical:
    "M0,10 L10,10 L13,1 L16,19 L19,2 L22,10 L40,10 L43,0 L46,20 L49,1 L52,10 L70,10 L73,2 L76,18 L79,3 L82,10 L100,10",
};

export function Topbar({ hasOpenCase, allContainedOrDismissed, posture, health, dryRunPending, onSetDryRun }) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const dryRun = health?.dry_run !== false; // default to dry-run assumed safe until known

  const statusClass =
    posture === "critical" ? "status-danger" : posture === "warning" ? "status-warn" : "";

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
    <>
      <div className={`posture-strip ${posture}`}>
        <span className="posture-label">Posture · {POSTURE_COPY[posture]}</span>
        <div className="posture-waveform">
          <svg viewBox="0 0 100 20" preserveAspectRatio="none">
            <path d={WAVEFORM_PATHS[posture]} />
          </svg>
        </div>
      </div>

      <header className="topbar">
        <div>
          <h1>Activity</h1>
          <p>Real-time events from protected resources</p>
        </div>

        <div className="topbar-actions">
          <span className={`status-pill ${statusClass}`}>
            <span className="status-dot"></span>
            {hasOpenCase ? "Incident detected" : allContainedOrDismissed ? "Contained" : "Operational"}
          </span>

          <button
            className={`dryrun-pill ${dryRun ? "" : "live"}`}
            onClick={handleArm}
            disabled={dryRunPending}
            title={dryRun ? "Panic actions are logged only — click to arm live mode" : "Live mode — click to return to dry-run"}
          >
            <ShieldAlert size={11} />
            {dryRun ? "Dry-run" : "Live"}
          </button>

          <button className="icon-button">
            <Settings size={15} />
          </button>
        </div>
      </header>

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
    </>
  );
}
