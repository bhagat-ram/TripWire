import { useEffect, useState } from "react";
import { ChevronRight, Folder, FileWarning, File } from "lucide-react";

function SeverityDot({ severity }) {
  return <span className={`tree-dot tree-dot-${severity}`} />;
}

function FileRow({ file, onSelectEvent, allEvents, isFlashing }) {
  const jumpToEvidence = () => {
    if (!onSelectEvent || file.severity === "untouched") return;
    const match = allEvents.find((e) => e.resource === file.path);
    if (match) onSelectEvent(match);
  };

  return (
    <button
      className={`tree-file-row ${file.severity !== "untouched" ? "tree-file-active" : ""} ${
        isFlashing ? "tree-file-flash" : ""
      }`}
      onClick={jumpToEvidence}
      disabled={file.severity === "untouched"}
      title={
        file.onDisk === false
          ? `${file.filename} — not currently on disk`
          : file.touchCount
          ? `${file.touchCount} touch${file.touchCount === 1 ? "" : "es"} · last ${file.lastEventTime}`
          : `${file.filename} — no activity yet`
      }
    >
      <SeverityDot severity={file.severity} />
      {file.onDisk === false ? <FileWarning size={11} /> : <File size={11} />}
      <span className="tree-file-name">{file.filename}</span>
      {file.touchCount > 0 && <span className="tree-file-count">{file.touchCount}</span>}
    </button>
  );
}

function FolderRow({ folder, expanded, onToggle, onSelectEvent, allEvents, isFlashing }) {
  return (
    <div className={`tree-folder severity-${folder.severity} ${isFlashing ? "tree-folder-flash" : ""}`}>
      <button className="tree-folder-row" onClick={onToggle}>
        <ChevronRight size={11} className={`tree-chevron ${expanded ? "expanded" : ""}`} />
        <SeverityDot severity={folder.severity} />
        <Folder size={12} />
        <span className="tree-folder-label">{folder.label}</span>
        {folder.kind === "random" && <span className="tree-folder-random-flag">random</span>}
        <span className="tree-folder-count">{folder.fileCount}</span>
      </button>

      {expanded && (
        <div className="tree-folder-children">
          {folder.files.map((file) => (
            <FileRow
              key={file.key}
              file={file}
              onSelectEvent={onSelectEvent}
              allEvents={allEvents}
              isFlashing={isFlashing && file.path === folder._flashPath}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Real-filesystem decoy tree, colored by worst severity per folder, with a
 * live pulse on whatever file (and its folder) the most recent event
 * actually touched — same "just arrived" signal as the activity feed's row
 * flash (see EventRow's isNew), applied here so watching this panel during
 * a live incident shows exactly where activity is landing in real time,
 * not just a static snapshot that happens to be colored.
 *
 * Folders auto-expand the first time they go non-"untouched", but stay
 * user-collapsible after that — an analyst who collapsed a noisy folder on
 * purpose shouldn't have it forced back open on every subsequent touch.
 */
export function FileTree({ tree, onSelectEvent, allEvents, lastArrivedId }) {
  const [expanded, setExpanded] = useState(() => new Set());
  const [autoExpanded, setAutoExpanded] = useState(() => new Set());
  const [flashPath, setFlashPath] = useState(null);
  const [flashFolderId, setFlashFolderId] = useState(null);

  // Fires once per new event id, not per render — finds the file that just
  // got touched and flashes it (and its folder) for ~1.4s, matching the
  // activity feed's row-flash timing so the two live cues feel consistent.
  useEffect(() => {
    if (!lastArrivedId) return undefined;
    const event = allEvents.find((e) => e.id === lastArrivedId);
    if (!event?.resource) return undefined;

    const owningFolder = tree.find((f) => f.files.some((file) => file.path === event.resource));

    setFlashPath(event.resource);
    setFlashFolderId(owningFolder?.id || null);
    // Auto-expand the folder that just lit up so the flash is actually
    // visible, not hidden inside a collapsed row.
    if (owningFolder) {
      setExpanded((prev) => new Set(prev).add(owningFolder.id));
    }

    const t = setTimeout(() => {
      setFlashPath(null);
      setFlashFolderId(null);
    }, 1400);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastArrivedId]);

  for (const folder of tree) {
    if (folder.severity !== "untouched" && !autoExpanded.has(folder.id)) {
      autoExpanded.add(folder.id);
      expanded.add(folder.id);
    }
  }

  const toggle = (id) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (tree.length === 0) {
    return <div className="tree-empty">Waiting for backend manifest…</div>;
  }

  return (
    <div className="file-tree">
      {tree.map((folder) => {
        const isFlashing = flashFolderId === folder.id;
        return (
          <FolderRow
            key={folder.id}
            folder={isFlashing ? { ...folder, _flashPath: flashPath } : folder}
            expanded={expanded.has(folder.id)}
            onToggle={() => toggle(folder.id)}
            onSelectEvent={onSelectEvent}
            allEvents={allEvents}
            isFlashing={isFlashing}
          />
        );
      })}
    </div>
  );
}
