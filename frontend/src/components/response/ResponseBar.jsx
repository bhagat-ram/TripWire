import { Check, Ban, Skull, WifiOff, ArrowUpRight, ShieldOff, FileDown, ShieldAlert } from "lucide-react";
import { downloadIncidentReport } from "../../data/incidentReport";

const STATUS_LABEL = {
  open: "Case requires action",
  escalated: "Escalated — awaiting SOC pickup",
  contained: "Case contained",
  dismissed: "Marked as false positive",
};

/**
 * Response actions now target the selected case rather than a single global
 * incident, and offer more than one way to close a case: contain it
 * (suspend/kill/isolate), escalate it to another team, or dismiss it as a
 * false positive. Every action updates that case's status and action log,
 * but only "Suspend" and "Kill" reach the real backend (POST /action ->
 * PanicController) — "Isolate host" and "Escalate to SOC" have no backend
 * endpoint and are logged locally only (see data/incidents.js). "Generate
 * report" always actually does something (a file download) regardless of
 * dry-run.
 */
export function ResponseBar({ incident, events, onRespond, lastActionResult, health }) {
  const isOpenCase = incident && (incident.status === "open" || incident.status === "escalated");
  // Same "default to safe until known" logic as the Topbar dry-run pill.
  const dryRun = health?.dry_run !== false;
  // Set the moment Kill/Suspend is clicked, cleared only by a real
  // response_ack from the backend — see respondToIncident (incidents.js)
  // and onResponseAck (useTripwireConnection.js).
  const isPending = Boolean(incident?.pendingAction);

  return (
    <section className="response-bar">
      <div className="response-info">
        <strong>Response</strong>
        <span>{incident ? STATUS_LABEL[incident.status] : "No case selected"}</span>
      </div>

      {dryRun && (
        <span className="dryrun-warning-flag" title="Panic Mode is in dry-run — Kill and Suspend will only be logged, not actually sent, until you arm live mode from the top bar.">
          <ShieldAlert size={11} />
          Dry-run — Kill/Suspend won't actually act
        </span>
      )}

      {lastActionResult && (
        <div className="response-transition">
          <span className="before">{lastActionResult.before}</span>
          <span className="arrow">→</span>
          <span className="after">{lastActionResult.after}</span>
        </div>
      )}

      <div className="response-actions">
        <button
          className="secondary-button"
          disabled={!incident}
          onClick={() => incident && downloadIncidentReport(incident, events)}
        >
          <FileDown size={11} />
          Generate report
        </button>

        <button
          className="secondary-button"
          disabled={!isOpenCase}
          onClick={() => onRespond(incident.id, "escalate")}
          title="Logged only — no ticketing system is wired up to actually notify SOC"
        >
          <ArrowUpRight size={11} />
          Escalate
        </button>

        <button
          className="secondary-button dismiss-button"
          disabled={!isOpenCase}
          onClick={() => onRespond(incident.id, "dismiss")}
        >
          <ShieldOff size={11} />
          Dismiss
        </button>

        <button
          className="secondary-button"
          disabled={!isOpenCase}
          onClick={() => onRespond(incident.id, "isolate")}
          title="Logged only — no backend endpoint actually isolates the host yet"
        >
          <WifiOff size={11} />
          Isolate host (logged only)
        </button>

        <button
          className={`secondary-button ${dryRun && isOpenCase ? "dryrun-armed-button" : ""}`}
          disabled={!isOpenCase || isPending}
          onClick={() => onRespond(incident.id, "kill")}
          title={dryRun ? "Dry-run — this will only log, not actually kill" : "Sends SIGTERM to the process for real"}
        >
          <Skull size={11} />
          {incident?.pendingAction === "kill"
            ? "Killing…"
            : `Kill process${dryRun && isOpenCase ? " (dry-run)" : ""}`}
        </button>

        <button
          className={`primary-button ${!isOpenCase && incident ? "contained-button" : ""} ${dryRun && isOpenCase ? "dryrun-armed-button" : ""}`}
          disabled={!isOpenCase || isPending}
          onClick={() => onRespond(incident.id, "suspend")}
          title={isOpenCase ? (dryRun ? "Dry-run — this will only log, not actually suspend" : "Suspends the process for real") : undefined}
        >
          {incident && !isOpenCase ? (
            <>
              <Check size={11} />
              {incident.status === "dismissed" ? "Dismissed" : "Contained"}
            </>
          ) : (
            <>
              <Ban size={11} />
              {incident?.pendingAction === "suspend"
                ? "Suspending…"
                : `Suspend process${dryRun && isOpenCase ? " (dry-run)" : ""}`}
            </>
          )}
        </button>
      </div>
    </section>
  );
}
