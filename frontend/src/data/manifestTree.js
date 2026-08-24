/**
 * manifestTree.js
 *
 * Builds the sidebar's file tree from real backend data — GET /manifest
 * (decoy_gen.py's actual placement map: ~/Desktop, ~/Documents, ~/Downloads,
 * /tmp/<random>, ~/.config, etc. — see backend/config.py's DECOY_PLACEMENTS)
 * joined against the live event feed, so each file/folder is colored by
 * what has actually touched it, not a mockup.
 *
 * There is no severity data on the manifest itself — decoy_gen.py only
 * knows what's on disk, not what's touched it. Severity comes from
 * matching each decoy's absolute path against event.resource (both are
 * the same real filesystem path, this isn't a name-based fuzzy match).
 */

const RANK = { untouched: 0, info: 1, warning: 2, critical: 3 };

function higherSeverity(a, b) {
  return RANK[b] > RANK[a] ? b : a;
}

/**
 * @param {{placements: object[], decoys: object[]}|null} manifest — raw GET /manifest body
 * @param {object[]} events — mapped events (mapTripwireEvent shape), used for their .resource/.severityRaw/.time
 * @returns {object[]} folder nodes: { id, label, kind, severity, fileCount, touchCount, files: [...] }
 */
export function buildManifestTree(manifest, events) {
  if (!manifest?.placements) return [];

  // One pass over events: path -> { severity, touchCount, lastEventTime }
  const byPath = new Map();
  for (const e of events) {
    if (!e.resource) continue;
    const prev = byPath.get(e.resource);
    const sev = e.severityRaw || "info";
    if (!prev) {
      byPath.set(e.resource, { severity: sev, touchCount: 1, lastEventTime: e.time });
    } else {
      byPath.set(e.resource, {
        severity: higherSeverity(prev.severity, sev),
        touchCount: prev.touchCount + 1,
        lastEventTime: e.time, // events arrive newest-first from the caller's list order in practice, but this is just "most recently seen in this pass" either way
      });
    }
  }

  const decoysByPlacement = new Map();
  for (const d of manifest.decoys || []) {
    if (!decoysByPlacement.has(d.placement_id)) decoysByPlacement.set(d.placement_id, []);
    decoysByPlacement.get(d.placement_id).push(d);
  }

  return manifest.placements.map((placement) => {
    const decoys = decoysByPlacement.get(placement.id) || [];
    let folderSeverity = "untouched";
    let touchCount = 0;

    const files = decoys
      .map((d) => {
        const hit = byPath.get(d.path);
        const severity = hit?.severity || "untouched";
        folderSeverity = higherSeverity(folderSeverity, severity);
        touchCount += hit?.touchCount || 0;
        return {
          key: d.key,
          filename: d.filename,
          path: d.path,
          severity,
          touchCount: hit?.touchCount || 0,
          lastEventTime: hit?.lastEventTime || null,
          onDisk: d.on_disk,
        };
      })
      // Loudest files first within a folder — the point of the tree is
      // spotting what's hot at a glance, not alphabetical browsing.
      .sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.filename.localeCompare(b.filename));

    return {
      id: placement.id,
      label: placement.label,
      kind: placement.kind, // "known" | "random"
      severity: folderSeverity,
      fileCount: files.length,
      touchCount,
      files,
    };
  });
}

/** Total touch count across the whole tree — used for the sidebar section badge. */
export function totalTouches(tree) {
  return tree.reduce((sum, folder) => sum + folder.touchCount, 0);
}
