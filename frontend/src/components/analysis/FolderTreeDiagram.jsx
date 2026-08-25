import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { FolderTree, Search, Radio, ChevronsDownUp, ChevronsUpDown } from "lucide-react";
import { buildManifestTree } from "../../data/manifestTree";
import { BACKEND_URL } from "../../services/tripwireSocket";

const LINE_COLOR = {
  untouched: "#c7cedb",
  info: "#7ba7e8",
  warning: "#d99a2b",
  critical: "#d65d5d",
};

/**
 * FolderTreeDiagram — box-and-connector-line diagram (same visual grammar
 * as an org chart / goal tree) built from the backend's actual decoy
 * placement map (GET /manifest — real paths like ~/Desktop, ~/Documents,
 * /tmp/<random>) joined against the live event feed.
 *
 * Folders lay out in a real CSS grid (wraps across rows, uses width AND
 * height) rather than a single-row org-chart strip — decoy_gen.py places
 * across 8+ real folders, and a single row either overflows or crushes
 * spacing. Root→folder connector lines are drawn as measured SVG paths
 * (via getBoundingClientRect, recomputed on layout change/resize) rather
 * than the classic pure-CSS ::before/::after trick, because that trick
 * only works for a single row of siblings and silently breaks once
 * folders wrap onto a second line. Folder→file connections stay simple
 * CSS (a small vertical stem) since files always sit directly under their
 * own folder in the same grid cell — no wrapping to solve there.
 *
 * Whatever file a new event just touched pulses live, along with its
 * folder — meant to be watched during a live incident, not read as a
 * static snapshot.
 */
export function FolderTreeDiagram({ events, lastArrivedId, onSelectEvent }) {
  const [manifest, setManifest] = useState(null);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(() => new Set());
  const [autoExpanded, setAutoExpanded] = useState(() => new Set());
  const [flashFolderId, setFlashFolderId] = useState(null);
  const [flashPath, setFlashPath] = useState(null);
  const [rootLines, setRootLines] = useState([]);

  const diagramRef = useRef(null);
  const rootRef = useRef(null);
  const folderRefs = useRef(new Map());

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
      .map((folder) => ({ ...folder, files: folder.files.filter((f) => f.filename.toLowerCase().includes(q)) }))
      .filter((folder) => folder.files.length > 0 || folder.label.toLowerCase().includes(q));
  }, [tree, query]);

  // Live pulse — fires once per new event id, finds the file it actually
  // touched, flashes that node + its parent folder node, and auto-expands
  // the folder so the flash is never hidden behind a collapsed branch.
  useEffect(() => {
    if (!lastArrivedId) return undefined;
    const event = events.find((e) => e.id === lastArrivedId);
    if (!event?.resource) return undefined;

    const owningFolder = tree.find((f) => f.files.some((file) => file.path === event.resource));
    setFlashPath(event.resource);
    setFlashFolderId(owningFolder?.id || null);
    if (owningFolder) setExpanded((prev) => new Set(prev).add(owningFolder.id));

    const t = setTimeout(() => {
      setFlashPath(null);
      setFlashFolderId(null);
    }, 1600);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastArrivedId]);

  // Auto-expand any folder the instant it goes from untouched to anything
  // else — persists beyond the 1.6s flash so a folder that went critical
  // stays open even after the pulse fades.
  for (const folder of filteredTree) {
    if (folder.severity !== "untouched" && !autoExpanded.has(folder.id)) {
      autoExpanded.add(folder.id);
      expanded.add(folder.id);
    }
  }

  // Measures the real, current pixel position of the root box and every
  // visible folder box (post-layout, so grid wrapping and any row-height
  // growth from an expanded folder above is already accounted for) and
  // builds one elbow path per folder — this is what makes the connector
  // lines correct regardless of which row a folder wrapped onto.
  const recomputeLines = () => {
    const container = diagramRef.current;
    const root = rootRef.current;
    if (!container || !root) return;

    const cRect = container.getBoundingClientRect();
    const rRect = root.getBoundingClientRect();
    const x1 = rRect.left - cRect.left + rRect.width / 2;
    const y1 = rRect.bottom - cRect.top;

    const lines = [];
    for (const folder of filteredTree) {
      const el = folderRefs.current.get(folder.id);
      if (!el) continue;
      const fRect = el.getBoundingClientRect();
      const x2 = fRect.left - cRect.left + fRect.width / 2;
      const y2 = fRect.top - cRect.top;
      const midY = y1 + (y2 - y1) / 2;
      lines.push({
        id: folder.id,
        color: LINE_COLOR[folder.severity] || LINE_COLOR.untouched,
        d: `M ${x1} ${y1} V ${midY} H ${x2} V ${y2}`,
      });
    }
    setRootLines(lines);
  };

  // Recompute whenever the visible folder set, expand state (row heights
  // shift when a folder's file list opens/closes), or search filter
  // changes layout.
  useLayoutEffect(() => {
    recomputeLines();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredTree, expanded]);

  // Also recompute on viewport/container resize (sidebar toggle, browser
  // resize, zoom) — layout effect above only covers React-driven changes.
  useEffect(() => {
    const onResize = () => recomputeLines();
    window.addEventListener("resize", onResize);
    let ro;
    if (diagramRef.current && "ResizeObserver" in window) {
      ro = new ResizeObserver(onResize);
      ro.observe(diagramRef.current);
    }
    return () => {
      window.removeEventListener("resize", onResize);
      if (ro) ro.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredTree, expanded]);

  const toggleFolder = (id) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => setExpanded(new Set(filteredTree.map((f) => f.id)));
  const collapseAll = () => setExpanded(new Set());

  const jumpToEvidence = (file) => {
    if (!onSelectEvent || file.severity === "untouched") return;
    const match = events.find((e) => e.resource === file.path);
    if (match) onSelectEvent(match);
  };

  const totalTouched = tree.reduce(
    (n, f) => n + f.files.filter((file) => file.severity !== "untouched").length,
    0
  );
  const totalFiles = tree.reduce((n, f) => n + f.fileCount, 0);

  return (
    <section className="analysis-panel">
      <div className="analysis-header">
        <div className="analysis-title">
          <FolderTree size={14} />
          <span>Decoy filesystem — live</span>
          <span className="tree-live-flag">
            <Radio size={9} />
            Live
          </span>
        </div>

        <div className="analysis-controls">
          <div className="analysis-search">
            <Search size={11} />
            <input
              type="text"
              placeholder="Filter files or folders…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <button className="icon-button" onClick={expandAll} title="Expand all folders">
            <ChevronsUpDown size={13} />
          </button>
          <button className="icon-button" onClick={collapseAll} title="Collapse all folders">
            <ChevronsDownUp size={13} />
          </button>
        </div>
      </div>

      <div className="analysis-subtitle">
        {totalFiles} decoys across {tree.length} real filesystem locations
        {totalTouched > 0 && ` · ${totalTouched} touched`}
      </div>

      {filteredTree.length === 0 ? (
        <div className="tree-empty">Waiting for backend manifest…</div>
      ) : (
        <div className="org-diagram" ref={diagramRef}>
          <svg className="org-lines-svg">
            {rootLines.map((line) => (
              <path key={line.id} className="org-line" d={line.d} stroke={line.color} />
            ))}
          </svg>

          <div className="org-node org-node-root" ref={rootRef}>
            Protected Resources
          </div>

          <div className="org-grid">
            {filteredTree.map((folder) => {
              const isExpanded = expanded.has(folder.id);
              const isFlashing = flashFolderId === folder.id;
              return (
                <div className="org-cell" key={folder.id}>
                  <button
                    ref={(el) => {
                      if (el) folderRefs.current.set(folder.id, el);
                      else folderRefs.current.delete(folder.id);
                    }}
                    className={`org-node org-node-folder severity-${folder.severity} ${
                      isFlashing ? "org-node-flash" : ""
                    }`}
                    onClick={() => toggleFolder(folder.id)}
                  >
                    <span className="org-node-label">{folder.label}</span>
                    <span className="org-node-meta">
                      {folder.fileCount} file{folder.fileCount === 1 ? "" : "s"}
                      {folder.touchCount > 0 && ` · ${folder.touchCount} touches`}
                    </span>
                  </button>

                  {isExpanded && folder.files.length > 0 && (
                    <>
                      <div className="org-cell-stem" />
                      <div className="org-cell-children">
                        {folder.files.map((file) => (
                          <button
                            key={file.key}
                            className={`org-node org-node-file severity-${file.severity} ${
                              flashPath === file.path ? "org-node-flash" : ""
                            } ${file.severity === "untouched" ? "org-node-inert" : ""}`}
                            onClick={() => jumpToEvidence(file)}
                            title={
                              file.touchCount
                                ? `${file.touchCount} touch${file.touchCount === 1 ? "" : "es"} — click to view evidence`
                                : "No activity yet"
                            }
                          >
                            <span className="org-node-label">{file.filename}</span>
                            {file.touchCount > 0 && <span className="org-node-badge">{file.touchCount}</span>}
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}
