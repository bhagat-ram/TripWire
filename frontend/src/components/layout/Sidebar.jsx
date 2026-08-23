import { ChevronDown } from "lucide-react";
import { DECOY_CATEGORIES, countForCategory } from "../../data/decoyResources";

export function Sidebar({
  events,
  selectedCategoryId,
  onSelectCategory,
  backendConnected,
  health,
  hasOpenCase,
  allContainedOrDismissed,
}) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">T</div>
        <div>
          <div className="brand-name">Tripwire</div>
          <div className="brand-subtitle">Detection & response</div>
        </div>
      </div>

      <div className="sidebar-section">
        <div className="sidebar-label">Resources</div>

        {DECOY_CATEGORIES.map((category) => {
          const Icon = category.icon;
          const count = countForCategory(category, events);
          return (
            <button
              key={category.id}
              className={`resource-item ${
                selectedCategoryId === category.id ? "active" : ""
              }`}
              onClick={() => onSelectCategory(category.id)}
            >
              <Icon size={15} />
              <span>{category.label}</span>
              <span className="resource-count">{count}</span>
            </button>
          );
        })}
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
