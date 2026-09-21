import {
  LayoutDashboard,
  Activity,
  SlidersHorizontal,
  ScanEye,
} from "lucide-react";

/**
 * Real navigation, not a placeholder menu: every item does real work.
 * Two flavors live in the same "Workflow" group now:
 *
 *  - `type: "scroll"` — Overview — still jumps (smooth-scroll) to a section
 *    on the one-page dashboard, exactly as before.
 *  - `type: "page"` — Live activity, Settings — their own routed pages
 *    (App.jsx's `page` state), not subsections.
 *
 * Live activity used to be a scroll target too, but on most screens it sat
 * close enough to Overview that jumping to it didn't look like anything
 * happened — so it graduated to its own page (ActivityPage), same as
 * Settings, and is no longer duplicated inline on the dashboard.
 *
 * Analysis/Incidents/Detection/Response used to be routed pages here too,
 * but they were blank placeholders that only ever duplicated the sections
 * already on the one-page dashboard, so they've been removed in favor of
 * the Settings page (thresholds, automation rules, dry-run — all
 * previously scattered across a modal and other pages).
 */
const SECTIONS = [
  { id: "section-overview", label: "Overview", icon: LayoutDashboard, type: "scroll" },
  { id: "activity", label: "Live activity", icon: Activity, type: "page" },
  { id: "settings", label: "Settings", icon: SlidersHorizontal, type: "page", badge: "mode" },
];

// System Audit — a different data source entirely (fanotify_watcher.py's
// full-system feed, not the decoy pipeline) with its own enable/disable
// lifecycle, kept in its own "System" group so that distinction stays
// visible rather than blending into Workflow.
const SYSTEM_SECTIONS = [{ id: "audit", label: "System audit", icon: ScanEye, badge: "fsMonitor" }];

export function SidebarNav({ activeId, dryRun, page, onNavigatePage, fsMonitorAlive }) {
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
              <span className="nav-icon">
                <Icon size={14} />
              </span>
              <span>{item.label}</span>

              {item.badge === "mode" && (
                <span className={`nav-badge ${dryRun ? "" : "nav-badge-live"}`}>
                  {dryRun ? "dry" : "live"}
                </span>
              )}
            </button>
          );
        })}
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
              <span className="nav-icon">
                <Icon size={14} />
              </span>
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
