import {
  LayoutDashboard,
  Activity,
  GitBranch,
  ShieldAlert,
  Radar,
  Zap,
  SlidersHorizontal,
  ScanEye,
} from "lucide-react";

/**
 * Real navigation, not a placeholder menu: every item does real work.
 * Two flavors live in the same "Workflow" group now:
 *
 *  - `type: "scroll"` — Overview, Live activity, Response — still jump
 *    (smooth-scroll) to a section on the one-page dashboard, exactly as
 *    before.
 *  - `type: "page"` — Analysis, Incidents, Detection — each now its own
 *    routed page (App.jsx's `page` state), not a subsection. These three
 *    were the ones with real room to grow (bigger visuals, status
 *    filtering, KPI strips — see AnalysisPage/IncidentsPage/DetectionPage),
 *    so they graduated off the single-page scroll; Overview/Live
 *    activity/Response stay put for now.
 *
 * "Automation rules" still opens the settings modal instead of navigating
 * anywhere, since that's a modal, not a page.
 */
const SECTIONS = [
  { id: "section-overview", label: "Overview", icon: LayoutDashboard, type: "scroll" },
  { id: "section-activity", label: "Live activity", icon: Activity, type: "scroll" },
  { id: "analysis", label: "Analysis", icon: GitBranch, type: "page" },
  { id: "incidents", label: "Incidents", icon: ShieldAlert, type: "page", badge: "openCases" },
  { id: "detection", label: "Detection", icon: Radar, type: "page" },
  { id: "section-response", label: "Response", icon: Zap, type: "scroll", badge: "mode" },
];

// System Audit — a different data source entirely (fanotify_watcher.py's
// full-system feed, not the decoy pipeline) with its own enable/disable
// lifecycle, kept in its own "System" group so that distinction stays
// visible rather than blending into Workflow.
const SYSTEM_SECTIONS = [{ id: "audit", label: "System audit", icon: ScanEye, badge: "fsMonitor" }];

export function SidebarNav({ activeId, openCaseCount, dryRun, onOpenSettings, page, onNavigatePage, fsMonitorAlive }) {
  const jumpTo = (id) => {
    // Scroll items only make sense on the dashboard page — if some other
    // page is showing, hop back first so the section being scrolled to
    // actually exists in the DOM.
    if (page !== "dashboard") onNavigatePage?.("dashboard");
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <>
      <div className="sidebar-section sidebar-nav">
        <div className="sidebar-label">Workflow</div>

        {SECTIONS.map((item) => {
          const Icon = item.icon;
          const isPage = item.type === "page";
          const isActive = isPage ? page === item.id : page === "dashboard" && activeId === item.id;

          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? "active" : ""}`}
              onClick={() => (isPage ? onNavigatePage?.(item.id) : jumpTo(item.id))}
            >
              <Icon size={13} />
              <span>{item.label}</span>

              {item.badge === "openCases" && openCaseCount > 0 && (
                <span className="nav-badge nav-badge-danger">{openCaseCount}</span>
              )}
              {item.badge === "mode" && (
                <span className={`nav-badge ${dryRun ? "" : "nav-badge-live"}`}>
                  {dryRun ? "dry" : "live"}
                </span>
              )}
            </button>
          );
        })}

        <button className="nav-item nav-item-modal" onClick={onOpenSettings} title="Configure automated response rules">
          <SlidersHorizontal size={13} />
          <span>Automation rules</span>
        </button>
      </div>

      <div className="sidebar-section sidebar-nav">
        <div className="sidebar-label">System</div>

        {SYSTEM_SECTIONS.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`nav-item ${page === item.id ? "active" : ""}`}
              onClick={() => onNavigatePage?.(item.id)}
            >
              <Icon size={13} />
              <span>{item.label}</span>

              {item.badge === "fsMonitor" && (
                <span className={`nav-badge ${fsMonitorAlive ? "nav-badge-live" : ""}`}>
                  {fsMonitorAlive ? "on" : "off"}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </>
  );
}
