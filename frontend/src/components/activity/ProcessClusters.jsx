import { useState } from "react";
import { AlertTriangle, Flame, FileText, ChevronDown, ChevronRight, GitBranch } from "lucide-react";
import { MITRE_LABELS } from "../../data/mockEvents";

const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };

const SEVERITY_META = {
  critical: { icon: Flame, className: "event-critical" },
  warning: { icon: AlertTriangle, className: "event-warning" },
  info: { icon: FileText, className: "" },
};

/**
 * Groups a flat event list into one card per (pid, process) — the "who did
 * what" view. A flat timeline shows *that* a resource was touched five
 * times; this shows *that the same process touched five different
 * resources*, which is the shape that actually reads as recon/exfil
 * behavior rather than five unrelated one-off reads.
 */
function buildClusters(events) {
  const map = new Map();

  for (const e of events) {
    const key = `${e.pid ?? "?"}|${e.process ?? "unknown"}`;
    if (!map.has(key)) {
      map.set(key, {
        key,
        process: e.process || "Unknown process",
        pid: e.pid,
        parentProcess: e.parentProcess,
        parentPid: e.parentPid,
        events: [],
        resources: new Map(), // resource path -> representative event (for click-through)
        mitre: new Map(), // technique id -> count
        maxSeverity: "info",
        firstAt: e.receivedAt ?? 0,
        lastAt: e.receivedAt ?? 0,
        firstTime: e.time,
        lastTime: e.time,
      });
    }

    const c = map.get(key);
    c.events.push(e);
    if (!c.resources.has(e.resource)) c.resources.set(e.resource, e);
    if (e.mitre) c.mitre.set(e.mitre, (c.mitre.get(e.mitre) || 0) + 1);
    if (SEVERITY_RANK[e.severityRaw] > SEVERITY_RANK[c.maxSeverity]) c.maxSeverity = e.severityRaw;

    const at = e.receivedAt ?? 0;
    if (at < c.firstAt) {
      c.firstAt = at;
      c.firstTime = e.time;
    }
    if (at >= c.lastAt) {
      c.lastAt = at;
      c.lastTime = e.time;
    }
  }

  return [...map.values()].sort((a, b) => {
    if (SEVERITY_RANK[b.maxSeverity] !== SEVERITY_RANK[a.maxSeverity]) {
      return SEVERITY_RANK[b.maxSeverity] - SEVERITY_RANK[a.maxSeverity];
    }
    if (b.resources.size !== a.resources.size) return b.resources.size - a.resources.size;
    return b.events.length - a.events.length;
  });
}

export function ProcessClusters({ events, onSelectEvent, focusEventId }) {
  const [expanded, setExpanded] = useState(() => new Set());

  if (events.length === 0) return null;

  const clusters = buildClusters(events);

  const toggle = (key) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });

  return (
    <div className="cluster-list">
      {clusters.map((c) => {
        const isOpen = expanded.has(c.key);
        const { icon: SeverityIcon, className: severityClass } = SEVERITY_META[c.maxSeverity];
        const resourceList = [...c.resources.entries()];
        const mitreList = [...c.mitre.entries()].sort((a, b) => b[1] - a[1]);
        const containsFocused = c.events.some((e) => e.id === focusEventId);

        return (
          <div
            key={c.key}
            className={`cluster-card ${severityClass} ${isOpen ? "cluster-open" : ""} ${
              containsFocused ? "cluster-focused" : ""
            }`}
          >
            <button className="cluster-header" onClick={() => toggle(c.key)}>
              <span className="cluster-chevron">
                {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              </span>

              <span className="cluster-severity-icon">
                <SeverityIcon size={13} />
              </span>

              <span className="cluster-process">
                {c.process}
                {c.pid && <span className="cluster-pid">#{c.pid}</span>}
              </span>

              {c.parentProcess && (
                <span className="cluster-lineage">
                  <GitBranch size={11} />
                  {c.parentProcess}
                  {c.parentPid && <span className="cluster-pid">#{c.parentPid}</span>}
                </span>
              )}

              <span className="cluster-spacer" />

              {resourceList.length > 1 && (
                <span className="cluster-stat">{resourceList.length} resources</span>
              )}
              <span className="cluster-stat cluster-stat-strong">
                {c.events.length} touch{c.events.length === 1 ? "" : "es"}
              </span>
              <span className="cluster-time">
                {c.firstTime}
                {c.lastTime !== c.firstTime ? ` → ${c.lastTime}` : ""}
              </span>
            </button>

            {isOpen && (
              <div className="cluster-body">
                {mitreList.length > 0 && (
                  <div className="cluster-chip-row">
                    {mitreList.map(([id, count]) => (
                      <span className="mitre-badge" key={id} title={MITRE_LABELS[id] || "Unknown technique"}>
                        {id} · {MITRE_LABELS[id] || "Unknown"}
                        {count > 1 ? ` ×${count}` : ""}
                      </span>
                    ))}
                  </div>
                )}

                <div className="cluster-resource-list">
                  {resourceList.map(([resource, event]) => (
                    <button
                      key={resource}
                      className={`cluster-resource-chip ${event.id === focusEventId ? "active" : ""}`}
                      onClick={() => onSelectEvent(event)}
                      title="Open this touch in the investigation drawer"
                    >
                      <FileText size={10} />
                      {event.filename || resource}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
