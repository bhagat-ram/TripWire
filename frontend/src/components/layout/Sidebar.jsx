import { useEffect, useMemo, useState } from "react";
import { ChevronDown, LayoutList, FolderTree, Search, Radio } from "lucide-react";
import { DECOY_CATEGORIES, countForCategory } from "../../data/decoyResources";
import { buildManifestTree } from "../../data/manifestTree";
import { FileTree } from "../sidebar/FileTree";
import { BACKEND_URL } from "../../services/tripwireSocket";
import { useScrollSpy } from "../../hooks/useScrollSpy";
import { SidebarNav } from "./SidebarNav";

const NAV_SECTION_IDS = [
  "section-overview",
  "section-activity",
  "section-incidents",
  "section-detection",
  "section-response",
];

/**
 * Sidebar — two ways to browse protected resources:
 *
 *  · List  — the original file-type category filter (spreadsheets, docs,
 *            etc.), still wired to the same onSelectCategory/ActivityFeed
 *            filtering as before. Good for "show me every .csv touch".
 *
 *  · Tree  — the real filesystem placement structure decoy_gen.py actually
 *            uses (~/Desktop, ~/Documents, /tmp/<random>, ~/.config, ...),
 *            colored by the worst severity seen in each folder. Good for
 *            "where is the intrusion actually happening" at a glance.
 *
 * Manifest is fetched here (not centralized in the connection hook) to
 * match the existing local-fetch precedent in OverviewCards.jsx, and
 * refetched on a light poll since decoy_gen.py's on-disk state (skipped_no_dir,
 * diverged, etc.) can change independently of the event stream.
 */
export function Sidebar({
  events,
  selectedCategoryId,
  onSelectCategory,
  backendConnected,
  health,
  hasOpenCase,
  allContainedOrDismissed,
  onSelectEvent,
  lastArrivedId,
  openCaseCount,
  onOpenSettings,
}) {
  const [view, setView] = useState("tree"); // "list" | "tree" — tree is the more useful default now
  const [manifest, setManifest] = useState(null);
  const [query, setQuery] = useState("");
  const activeSection = useScrollSpy(NAV_SECTION_IDS);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      fetch(`${BACKEND_URL}/manifest`)
        .then((res) => (res.ok ? res.json() : null))
        .then((body) => {
          if (!cancelled && body) setManifest(body);
        })
        .catch(() => {});
    };
    load();
    const id = setInterval(load, 30000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const tree = useMemo(() => buildManifestTree(manifest, events), [manifest, events]);

  const filteredTree = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return tree;
    return tree
      .map((folder) => ({
        ...folder,
        files: folder.files.filter((f) => f.filename.toLowerCase().includes(q)),
      }))
      .filter((folder) => folder.files.length > 0 || folder.label.toLowerCase().includes(q));
  }, [tree, query]);

  const severityCounts = useMemo(() => {
    let warning = 0;
    let critical = 0;
    for (const folder of tree) {
      for (const f of folder.files) {
        if (f.severity === "warning") warning++;
        if (f.severity === "critical") critical++;
      }
    }
    return { warning, critical };
  }, [tree]);

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

      <div className="sidebar-section sidebar-resources">
        <div className="sidebar-section-header">
          <div className="sidebar-label">Resources</div>

          <div className="view-toggle">
            <button
              className={view === "list" ? "active" : ""}
              onClick={() => setView("list")}
              title="Filter by file type"
              aria-label="List view"
            >
              <LayoutList size={11} />
            </button>
            <button
              className={view === "tree" ? "active" : ""}
              onClick={() => setView("tree")}
              title="Browse by real filesystem location, live"
              aria-label="Tree view"
            >
              <FolderTree size={11} />
            </button>
          </div>
        </div>

        {view === "tree" && backendConnected && (
          <div className="tree-live-flag">
            <Radio size={9} />
            <span>Live</span>
          </div>
        )}

        {(severityCounts.warning > 0 || severityCounts.critical > 0) && (
          <div className="sidebar-severity-summary">
            {severityCounts.critical > 0 && (
              <span className="severity-chip severity-chip-critical">
                {severityCounts.critical} critical
              </span>
            )}
            {severityCounts.warning > 0 && (
              <span className="severity-chip severity-chip-warning">
                {severityCounts.warning} warning
              </span>
            )}
          </div>
        )}

        {view === "tree" && (
          <div className="sidebar-search">
            <Search size={11} />
            <input
              type="text"
              placeholder="Filter files…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        )}

        {view === "list" ? (
          <div className="resource-list">
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
        ) : (
          <FileTree
            tree={filteredTree}
            onSelectEvent={onSelectEvent}
            allEvents={events}
            lastArrivedId={lastArrivedId}
          />
        )}
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
