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

// Attribution confidence, ranked worst (least certain) to best — used so a
// folder/file's badge reflects the *least* confident attribution seen
// across its touches, same "worst case wins" logic severity already uses.
// An analyst scanning the tree should never see "high confidence" on a file
// that also had an "unknown" touch hiding behind it.
const CONFIDENCE_RANK = { unknown: 0, ambiguous: 1, high: 2 };

function higherSeverity(a, b) {
  return RANK[b] > RANK[a] ? b : a;
}

function worseConfidence(a, b) {
  if (!a) return b;
  if (!b) return a;
  return CONFIDENCE_RANK[b] < CONFIDENCE_RANK[a] ? b : a;
}

/**
 * @param {{placements: object[], decoys: object[]}|null} manifest — raw GET /manifest body
 * @param {object[]} events — mapped events (mapTripwireEvent shape), used for their .resource/.severityRaw/.time
 * @returns {object[]} folder nodes: { id, label, kind, severity, fileCount, touchCount, files: [...] }
 */
export function buildManifestTree(manifest, events) {
  if (!manifest?.placements) return [];

  // One pass over events: path -> { severity, touchCount, lastEventTime, confidence, mitre }
  const byPath = new Map();
  for (const e of events) {
    if (!e.resource) continue;
    const prev = byPath.get(e.resource);
    const sev = e.severityRaw || "info";
    const conf = e.attributionConfidence || null;
    if (!prev) {
      byPath.set(e.resource, {
        severity: sev,
        touchCount: 1,
        lastEventTime: e.time,
        confidence: conf,
        mitre: e.mitre || null,
      });
    } else {
      byPath.set(e.resource, {
        severity: higherSeverity(prev.severity, sev),
        touchCount: prev.touchCount + 1,
        lastEventTime: e.time, // events arrive newest-first from the caller's list order in practice, but this is just "most recently seen in this pass" either way
        confidence: worseConfidence(prev.confidence, conf),
        mitre: e.mitre || prev.mitre,
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
          confidence: hit?.confidence || null,
          mitre: hit?.mitre || null,
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

/**
 * Attribution-confidence breakdown across every touched file in the tree —
 * the same high/ambiguous/unknown categories backend/report.py reports on
 * the raw event log, just computed here from the already-built tree so the
 * Analysis panel can show it without a second pass over `events`.
 */
export function confidenceBreakdown(tree) {
  const counts = { high: 0, ambiguous: 0, unknown: 0 };
  for (const folder of tree) {
    for (const file of folder.files) {
      if (file.severity === "untouched") continue;
      const key = file.confidence && counts[file.confidence] !== undefined ? file.confidence : "unknown";
      counts[key] += 1;
    }
  }
  return counts;
}
