import { ChevronDown } from "lucide-react";
import { useScrollSpy } from "../../hooks/useScrollSpy";
import { SidebarNav } from "./SidebarNav";

const NAV_SECTION_IDS = [
  "section-overview",
  "section-activity",
  "section-response",
];

/**
 * Sidebar — workflow navigation + connection status.
 *
 * Nav items are a mix now: Overview/Live activity/Response are still
 * scroll-spy sections on the one-page dashboard (NAV_SECTION_IDS above
 * only tracks those three), while Analysis/Incidents/Detection graduated
 * into their own routed pages — see App.jsx's `page` state and
 * SidebarNav's SECTIONS array for which is which.
 */
export function Sidebar({
  backendConnected,
  health,
  hasOpenCase,
  allContainedOrDismissed,
  openCaseCount,
  onOpenSettings,
  page,
  onNavigatePage,
}) {
  const activeSection = useScrollSpy(NAV_SECTION_IDS);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          {/* Two posts + a taut line between them, snapped by a diamond
              trip-spark at the break point — the mark reads as "tripwire"
              rather than a generic shield/lock, matching the product name. */}
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="4" cy="19" r="2.6" fill="currentColor" />
            <circle cx="20" cy="5" r="2.6" fill="currentColor" />
            <path d="M6 17.3 L10.2 13.1 M13.8 9.9 L18 5.7" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
            <path d="M12 8 L15 12 L12 16 L9 12 Z" fill="currentColor" />
          </svg>
        </div>
        <div>
          <div className="brand-name">Tripwire</div>
          <div className="brand-subtitle">Detection & response</div>
        </div>
      </div>

      <SidebarNav
        activeId={activeSection}
        openCaseCount={openCaseCount}
        dryRun={health ? health.dry_run !== false : true}
        onOpenSettings={onOpenSettings}
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
