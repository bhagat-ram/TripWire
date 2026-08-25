import { ChevronDown } from "lucide-react";
import { DECOY_CATEGORIES, countForCategory } from "../../data/decoyResources";
import { useScrollSpy } from "../../hooks/useScrollSpy";
import { SidebarNav } from "./SidebarNav";

const NAV_SECTION_IDS = [
  "section-overview",
  "section-activity",
  "section-analysis",
  "section-incidents",
  "section-detection",
  "section-response",
];

/**
 * Sidebar — navigation + the original file-type resource filter.
 *
 * The live folder/file tree diagram lives in the main content area now
 * (see components/analysis/FolderTreeDiagram.jsx, rendered as
 * #section-analysis in App.jsx) — a real org-chart-style diagram deserves
 * page-width room to actually show its connector lines, not a 212px rail.
 * "Analysis" in the workflow nav below jumps straight to it.
 */
export function Sidebar({
  events,
  selectedCategoryId,
  onSelectCategory,
  backendConnected,
  health,
  hasOpenCase,
  allContainedOrDismissed,
  openCaseCount,
  onOpenSettings,
}) {
  const activeSection = useScrollSpy(NAV_SECTION_IDS);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">T</div>
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
      />

      <div className="sidebar-section">
        <div className="sidebar-label">Resources</div>
        <div className="resource-list">
          {DECOY_CATEGORIES.map((category) => {
            const Icon = category.icon;
            const count = countForCategory(category, events);
            return (
              <button
                key={category.id}
                className={`resource-item ${selectedCategoryId === category.id ? "active" : ""}`}
                onClick={() => onSelectCategory(category.id)}
              >
                <Icon size={15} />
                <span>{category.label}</span>
                <span className="resource-count">{count}</span>
              </button>
            );
          })}
        </div>
      </div>

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
