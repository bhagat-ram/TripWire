import { useEffect, useState } from "react";
import { Shield, BarChart3, AlertTriangle, Flame } from "lucide-react";
import { DECOY_CATEGORIES } from "../../data/decoyResources";
import { BACKEND_URL } from "../../services/tripwireSocket";

// Fallback only — used until GET /manifest answers (or if the backend is
// unreachable). The real count comes from the backend, since decoy_gen.py's
// DECOY_SPECS list (21 entries, 23 on macOS) has drifted from any number
// hardcoded here before, and will again.
const FALLBACK_PROTECTED_RESOURCES = 21;

export function OverviewCards({
  events,
  incidents,
  severityFilter,
  onToggleSeverityFilter,
  lastArrivedId,
}) {
  const [pulsing, setPulsing] = useState(false);
  const [protectedCount, setProtectedCount] = useState(null);

  useEffect(() => {
    if (!lastArrivedId) return;
    setPulsing(true);
    const t = setTimeout(() => setPulsing(false), 900);
    return () => clearTimeout(t);
  }, [lastArrivedId]);

  useEffect(() => {
    let cancelled = false;
    fetch(`${BACKEND_URL}/manifest`)
      .then((res) => (res.ok ? res.json() : null))
      .then((body) => {
        if (!cancelled && body?.decoys) setProtectedCount(body.decoys.length);
      })
      .catch(() => {
        // backend unreachable — fall back to the static count below
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const warningCount = events.filter((e) => e.severityRaw === "warning").length;
  const criticalCount = events.filter((e) => e.severityRaw === "critical").length;
  const openCases = incidents.filter((i) => i.status === "open" || i.status === "escalated").length;

  return (
    <section className="overview">
      <div className={`overview-card ${pulsing ? "pulse" : ""}`}>
        <div className="overview-icon">
          <Shield size={18} />
        </div>
        <div className="overview-content">
          <span className="overview-label">Resources</span>
          <strong>{protectedCount ?? FALLBACK_PROTECTED_RESOURCES}</strong>
          <span className="overview-meta">
            Protected across {DECOY_CATEGORIES.length - 1} categories
          </span>
        </div>
      </div>

      <div className={`overview-card ${pulsing ? "pulse" : ""}`}>
        <div className="overview-icon">
          <BarChart3 size={18} />
        </div>
        <div className="overview-content">
          <span className="overview-label">Events today</span>
          <strong>{events.length}</strong>
          <span className="overview-meta">
            {openCases > 0
              ? `${openCases} open case${openCases === 1 ? "" : "s"}`
              : "No suspicious activity"}
          </span>
        </div>
      </div>

      <button
        type="button"
        className={`overview-card ${severityFilter === "warning" ? "filter-active" : ""}`}
        onClick={() => onToggleSeverityFilter("warning")}
      >
        <div className="overview-icon warning">
          <AlertTriangle size={18} />
        </div>
        <div className="overview-content">
          <span className="overview-label">Warnings</span>
          <strong>{warningCount}</strong>
          <span className="overview-meta">Click to filter activity</span>
        </div>
      </button>

      <button
        type="button"
        className={`overview-card ${severityFilter === "critical" ? "filter-active" : ""}`}
        onClick={() => onToggleSeverityFilter("critical")}
      >
        <div className="overview-icon critical">
          <Flame size={18} />
        </div>
        <div className="overview-content">
          <span className="overview-label">Critical</span>
          <strong>{criticalCount}</strong>
          <span className="overview-meta">
            {openCases > 0 ? "Investigation required" : "Click to filter activity"}
          </span>
        </div>
      </button>
    </section>
  );
}
