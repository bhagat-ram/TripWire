import { Sparkles, Flame, AlertTriangle, Users, Activity } from "lucide-react";
import { FolderTreeDiagram } from "./FolderTreeDiagram";

/**
 * Analysis — promoted from a scroll-spy section to its own routed page
 * (see SidebarNav's SECTIONS: this is now `type: "page"`, not `type:
 * "scroll"`). The org-chart diagram itself (FolderTreeDiagram) is
 * untouched — it already earns full-page width — this wrapper just gives
 * the page real page furniture: a header and a KPI strip built from the
 * same `events` data, using the same `.overview-card` visual language as
 * the dashboard's Overview cards so the two "feel" like the same product.
 *
 * The AI-insights badge is a deliberate placeholder, not a stub button —
 * flagged per product decision to scope AI integration OUT of this pass.
 * Wire it up (pattern summarization, anomaly commentary, etc.) later
 * without needing to touch this page's layout.
 */
export function AnalysisPage({ events, lastArrivedId, onSelectEvent }) {
  const criticalTouches = events.filter((e) => e.severityRaw === "critical").length;
  const warningTouches = events.filter((e) => e.severityRaw === "warning").length;
  const distinctProcesses = new Set(events.map((e) => e.process)).size;

  return (
    <div className="page-view">
      <div className="page-header">
        <div>
          <h1>Analysis</h1>
          <p>Live decoy filesystem map — where activity is landing, and how far it's spreading.</p>
        </div>
        <span className="ai-soon-badge" title="AI-assisted pattern analysis — planned, not built yet">
          <Sparkles size={11} />
          AI insights · coming soon
        </span>
      </div>

      <div className="overview page-kpi-strip">
        <div className="overview-card">
          <div className="overview-icon critical">
            <Flame size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Critical touches</span>
            <strong>{criticalTouches}</strong>
            <span className="overview-meta">Across all decoys</span>
          </div>
        </div>

        <div className="overview-card">
          <div className="overview-icon warning">
            <AlertTriangle size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Warning touches</span>
            <strong>{warningTouches}</strong>
            <span className="overview-meta">Across all decoys</span>
          </div>
        </div>

        <div className="overview-card">
          <div className="overview-icon">
            <Users size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Distinct processes</span>
            <strong>{distinctProcesses}</strong>
            <span className="overview-meta">Seen touching a decoy</span>
          </div>
        </div>

        <div className="overview-card">
          <div className="overview-icon">
            <Activity size={18} />
          </div>
          <div className="overview-content">
            <span className="overview-label">Total events</span>
            <strong>{events.length}</strong>
            <span className="overview-meta">Loaded this session</span>
          </div>
        </div>
      </div>

      <FolderTreeDiagram events={events} lastArrivedId={lastArrivedId} onSelectEvent={onSelectEvent} />
    </div>
  );
}
