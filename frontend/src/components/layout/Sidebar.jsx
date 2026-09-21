import { ChevronDown } from "lucide-react";
import tripwireLogo from "../../assets/tripwire-logo.png";
import { useScrollSpy } from "../../hooks/useScrollSpy";
import { SidebarNav } from "./SidebarNav";

const NAV_SECTION_IDS = ["section-overview"];

/**
 * Sidebar — workflow navigation + connection status.
 *
 * Only Overview is still a scroll-spy section on the one-page dashboard
 * now (NAV_SECTION_IDS above). Live activity and Settings are both routed
 * pages — see App.jsx's `page` state and SidebarNav's SECTIONS array.
 * (Analysis/Incidents/Detection/Response used to be routed pages here too,
 * but they were blank placeholders that only duplicated the dashboard's
 * own sections, so they've been removed — Settings replaces that slot.)
 */
export function Sidebar({
  backendConnected,
  health,
  hasOpenCase,
  allContainedOrDismissed,
  page,
  onNavigatePage,
}) {
  const activeSection = useScrollSpy(NAV_SECTION_IDS);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <img
            src={tripwireLogo}
            alt="Tripwire"
            className="brand-mark-logo"
          />
        </div>
        <div>
          <div className="brand-name">Tripwire</div>
          <div className="brand-subtitle">Detection & response</div>
        </div>
      </div>

      <SidebarNav
        activeId={activeSection}
        dryRun={health ? health.dry_run !== false : true}
        page={page}
        onNavigatePage={onNavigatePage}
        fsMonitorAlive={!!health?.fs_monitor_alive}
      />

      <div className="sidebar-bottom">
        <div className="connection">
          <span
            className="connection-dot"
            style={{
              backgroundColor: backendConnected ? "var(--safe-dot)" : "var(--text-quiet)",
              boxShadow: backendConnected ? "0 0 0 3px var(--safe-dim)" : "none",
            }}
          ></span>

          <div>
            <div className="connection-title">
              {!backendConnected
                ? "Backend disconnected"
                : hasOpenCase
                ? "Cases need attention"
                : allContainedOrDismissed
                ? "All cases resolved"
                : "System operational"}
            </div>

            <div className="connection-subtitle">
              {backendConnected
                ? health
                  ? `Watcher ${health.watcher_alive ? "alive" : "down"} · ${health.dead_letter_count} dead-lettered`
                  : "Connected"
                : "Waiting for backend at 127.0.0.1:5050"}
            </div>
          </div>

          <ChevronDown size={14} />
        </div>
      </div>
    </aside>
  );
}
