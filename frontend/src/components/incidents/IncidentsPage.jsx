import { useState } from "react";
import { Sparkles, Flame, AlertTriangle, Ban, ShieldOff } from "lucide-react";
import { IncidentQueue } from "./IncidentQueue";

const STATUS_FILTERS = [
  { key: "all", label: "All" },
  { key: "open", label: "Open" },
  { key: "escalated", label: "Escalated" },
  { key: "contained", label: "Contained" },
  { key: "dismissed", label: "Dismissed" },
];

/**
 * Incidents — promoted from a scroll-spy section to its own routed page.
 * IncidentQueue itself (the actual triage list — cards, mitigation status,
 * remove/clear-resolved) is unchanged; this wrapper adds the "tracking"
 * layer the flat list didn't have room for: a status breakdown (KPI strip,
 * same visual language as Overview/Analysis) and status filter chips so a
 * long queue can be narrowed to just what needs attention right now.
 *
 * Filtering happens here, not inside IncidentQueue — onClearResolved etc.
 * still act on the real, full incident list regardless of which subset is
 * currently visible, so "Clear resolved" always means all resolved cases,
 * not just the ones the current filter happens to show.
 *
 * AI-summaries badge: placeholder only, per product decision to scope AI
 * integration out of this pass — see AnalysisPage's docstring for the same
 * note. "Incident finding/tracking" is exactly where an AI-written case
 * summary would earn its keep later (condensing eventIds/actionLog into a
 * one-line brief), so this is the natural slot for it.
 */
export function IncidentsPage({ incidents, selectedIncidentId, onSelect, onRemove, onClearResolved }) {
  const [statusFilter, setStatusFilter] = useState("all");

  const counts = {
    open: incidents.filter((i) => i.status === "open").length,
    escalated: incidents.filter((i) => i.status === "escalated").length,
    contained: incidents.filter((i) => i.status === "contained").length,
    dismissed: incidents.filter((i) => i.status === "dismissed").length,
  };

  const visible = statusFilter === "all" ? incidents : incidents.filter((i) => i.status === statusFilter);

  return (
    <div className="page-view">
      <div className="page-header">
        <div>
          <h1>Incidents</h1>
          <p>Every distinct suspicious process, tracked as its own case from first touch to resolution.</p>
        </div>
        <span className="ai-soon-badge" title="AI-written case summaries — planned, not built yet">
          <Sparkles size={11} />
          AI summaries · coming soon
        </span>
      </div>

      <div className="overview page-kpi-strip">
        <button
          type="button"
          className={`overview-card ${statusFilter === "open" ? "filter-active" : ""}`}
          onClick={() => setStatusFilter((f) => (f === "open" ? "all" : "open"))}
        >
          <div className="overview-icon critical">
            <Flame size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Open</span>
            <strong>{counts.open}</strong>
            <span className="overview-meta">Click to filter</span>
          </div>
        </button>

        <button
          type="button"
          className={`overview-card ${statusFilter === "escalated" ? "filter-active" : ""}`}
          onClick={() => setStatusFilter((f) => (f === "escalated" ? "all" : "escalated"))}
        >
          <div className="overview-icon warning">
            <AlertTriangle size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Escalated</span>
            <strong>{counts.escalated}</strong>
            <span className="overview-meta">Click to filter</span>
          </div>
        </button>

        <button
          type="button"
          className={`overview-card ${statusFilter === "contained" ? "filter-active" : ""}`}
          onClick={() => setStatusFilter((f) => (f === "contained" ? "all" : "contained"))}
        >
          <div className="overview-icon">
            <Ban size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Contained</span>
            <strong>{counts.contained}</strong>
            <span className="overview-meta">Click to filter</span>
          </div>
        </button>

        <button
          type="button"
          className={`overview-card ${statusFilter === "dismissed" ? "filter-active" : ""}`}
          onClick={() => setStatusFilter((f) => (f === "dismissed" ? "all" : "dismissed"))}
        >
          <div className="overview-icon">
            <ShieldOff size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Dismissed</span>
            <strong>{counts.dismissed}</strong>
            <span className="overview-meta">Click to filter</span>
          </div>
        </button>
      </div>

      <div className="incident-status-filters">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.key}
            className={`severity-chip ${statusFilter === f.key ? "active warning" : ""}`}
            onClick={() => setStatusFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>

      <IncidentQueue
        incidents={visible}
        selectedIncidentId={selectedIncidentId}
        onSelect={onSelect}
        onRemove={onRemove}
        onClearResolved={onClearResolved}
      />
    </div>
  );
}
