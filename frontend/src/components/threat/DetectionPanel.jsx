import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Ban,
  Check,
  ArrowUpRight,
  ShieldOff,
  ShieldCheck,
  ShieldQuestion,
  ShieldAlert,
  Radar,
  Zap,
} from "lucide-react";
import { MITRE_LABELS } from "../../data/mockEvents";
import { MITRE_DETAILS } from "../../data/previewContent";

const STATUS_COPY = {
  open: { title: (i) => i.title, icon: AlertTriangle, statusClass: "status-check-danger" },
  escalated: {
    title: (i) => `${i.title} — escalated`,
    icon: ArrowUpRight,
    statusClass: "status-check-danger",
  },
  contained: { title: () => "Incident contained", icon: Ban, statusClass: "" },
  dismissed: { title: () => "Marked as false positive", icon: ShieldOff, statusClass: "" },
};

// Worst (least certain) confidence wins — same convention the incident
// queue and analysis tree use, so a case's headline attribution reflects
// the least confident touch in its evidence trail, not just the latest.
const CONFIDENCE_RANK = { unknown: 0, ambiguous: 1, high: 2 };

const CONFIDENCE_META = {
  high: {
    label: "High",
    icon: ShieldCheck,
    className: "confidence-high",
    hint: "A single, unambiguous process candidate was live at time of touch.",
  },
  ambiguous: {
    label: "Ambiguous",
    icon: ShieldAlert,
    className: "confidence-ambiguous",
    hint: "Multiple processes were plausible candidates — the reported PID is a best guess.",
  },
  unknown: {
    label: "Unknown",
    icon: ShieldQuestion,
    className: "confidence-unknown",
    hint: "No process candidate could be attributed to this touch.",
  },
};

/** Aggregates a list of events by attribution confidence into { high, ambiguous, unknown } counts. */
function confidenceCounts(evts) {
  const counts = { high: 0, ambiguous: 0, unknown: 0 };
  for (const e of evts) {
    const key = e.attributionConfidence && counts[e.attributionConfidence] !== undefined
      ? e.attributionConfidence
      : "unknown";
    counts[key] += 1;
  }
  return counts;
}

/** Aggregates a list of events by MITRE technique id, sorted loudest-first. */
function techniqueCounts(evts) {
  const counts = new Map();
  for (const e of evts) {
    if (!e.mitre) continue;
    counts.set(e.mitre, (counts.get(e.mitre) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

export function DetectionPanel({ incident, events, thresholds, thresholdUpdateError, onApplyThresholds }) {
  const active = incident && (incident.status === "open" || incident.status === "escalated");

  const [local, setLocal] = useState(thresholds);

  useEffect(() => setLocal(thresholds), [thresholds]);

  const commit = (next) => {
    // Keep critical strictly above warning so the pair always stays valid.
    const safe = { warning: next.warning, critical: Math.max(next.critical, next.warning + 1) };
    setLocal(safe);
    onApplyThresholds(safe);
  };

  const touchCounts = events.map((e) => e.touchCount).filter((n) => typeof n === "number");
  const wouldWarn = touchCounts.filter((n) => n >= local.warning && n < local.critical).length;
  const wouldEscalate = touchCounts.filter((n) => n >= local.critical).length;

  const copy = incident ? STATUS_COPY[incident.status] || STATUS_COPY.open : null;
  const StatusIcon = copy?.icon || Check;

  // Full evidence trail for the selected case, oldest first — this is what
  // turns "one status line" into an actual investigation timeline: exactly
  // when the process first touched a decoy, when it crossed each threshold,
  // and what technique each touch mapped to.
  const evidence = useMemo(() => {
    if (!incident) return [];
    const idSet = new Set(incident.eventIds);
    return events
      .filter((e) => idSet.has(e.id))
      .slice()
      .sort((a, b) => (a.receivedAt ?? 0) - (b.receivedAt ?? 0));
  }, [incident, events]);

  const caseConfidenceCounts = useMemo(() => confidenceCounts(evidence), [evidence]);
  const worstCaseConfidence = evidence.reduce((worst, e) => {
    const conf = e.attributionConfidence;
    if (!conf) return worst;
    if (!worst || CONFIDENCE_RANK[conf] < CONFIDENCE_RANK[worst]) return conf;
    return worst;
  }, null);

  const caseTechniques = useMemo(() => techniqueCounts(evidence), [evidence]);

  // First evidence row that pushed the running touch count at/over each
  // configured threshold — the exact moment the case would have opened
  // (warning) or escalated (critical) under the *current* slider values,
  // not just whatever thresholds were live when the event first arrived.
  const warningCrossedAt = evidence.find((e) => (e.touchCount ?? 0) >= local.warning);
  const criticalCrossedAt = evidence.find((e) => (e.touchCount ?? 0) >= local.critical);

  // Detection-engine-wide stats — meaningful even with no case selected,
  // since it reflects everything the classifier/attribution pipeline has
  // seen across the whole event log, not just the one case in focus.
  const globalConfidence = useMemo(() => confidenceCounts(events), [events]);
  const globalTechniques = useMemo(() => techniqueCounts(events), [events]);

  return (
    <section className="detection-section">
      <div className="section-heading">
        <div>
          <h2>Detection</h2>
          <p>Detection, attribution confidence, and technique mapping for the selected case.</p>
        </div>
      </div>

      <div className={`detection-card ${active ? "detection-active" : ""}`}>
        <div className="detection-status">
          <div className={`status-check ${active ? "status-check-danger" : ""}`}>
            <StatusIcon size={17} />
          </div>

          <div>
            <div className="detection-title">
              {incident ? copy.title(incident) : "No case selected"}
            </div>

            <div className="detection-description">
              {incident
                ? incident.description
                : "Select a case from the incident queue to see detection details, or wait for new activity."}
            </div>
          </div>
        </div>

        <div className="detection-fields">
          <div className="field">
            <span>Process</span>
            <strong>{incident?.process || "—"}</strong>
          </div>

          <div className="field">
            <span>PID</span>
            <strong>{incident?.pid || "—"}</strong>
          </div>

          <div className="field">
            <span>Severity</span>
            <strong className={active ? "critical-text" : ""}>{incident?.severity || "—"}</strong>
          </div>

          <div className="field">
            <span>MITRE ATT&CK</span>
            <strong>{incident?.mitre || "—"}</strong>
          </div>
        </div>
      </div>

      {incident && (
        <div className="detection-depth-grid">
          {/* ── Attribution confidence for this case ── */}
          <div className="detection-subpanel">
            <div className="detection-subpanel-title">
              <ShieldCheck size={11} />
              Attribution confidence
            </div>

            {worstCaseConfidence ? (
              <>
                <div className={`confidence-headline ${CONFIDENCE_META[worstCaseConfidence].className}`}>
                  {(() => {
                    const Icon = CONFIDENCE_META[worstCaseConfidence].icon;
                    return <Icon size={13} />;
                  })()}
                  <span>{CONFIDENCE_META[worstCaseConfidence].label} confidence (worst touch in trail)</span>
                </div>
                <p className="detection-subpanel-hint">{CONFIDENCE_META[worstCaseConfidence].hint}</p>
              </>
            ) : (
              <p className="detection-subpanel-hint">No attribution data on this case's evidence yet.</p>
            )}

            <div className="analysis-stat-chips">
              <span className="confidence-chip confidence-high" title={CONFIDENCE_META.high.hint}>
                {caseConfidenceCounts.high} high
              </span>
              <span className="confidence-chip confidence-ambiguous" title={CONFIDENCE_META.ambiguous.hint}>
                {caseConfidenceCounts.ambiguous} ambiguous
              </span>
              <span className="confidence-chip confidence-unknown" title={CONFIDENCE_META.unknown.hint}>
                {caseConfidenceCounts.unknown} unknown
              </span>
            </div>
          </div>

          {/* ── Techniques observed in this case ── */}
          <div className="detection-subpanel">
            <div className="detection-subpanel-title">
              <Radar size={11} />
              Techniques observed
            </div>

            {caseTechniques.length === 0 ? (
              <p className="detection-subpanel-hint">No technique has been mapped for this case yet.</p>
            ) : (
              <div className="technique-breakdown-list">
                {caseTechniques.map(([id, count]) => {
                  const detail = MITRE_DETAILS[id];
                  return (
                    <div key={id} className="technique-breakdown-row">
                      <div>
                        <strong>{id}</strong>
                        <span>{detail?.name || MITRE_LABELS[id] || "Unknown technique"}</span>
                      </div>
                      <span className="mitre-badge">{detail?.tactic || "Technique"}</span>
                      <span className="technique-breakdown-count">{count}×</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* ── Case timeline ── */}
          <div className="detection-subpanel detection-subpanel-wide">
            <div className="detection-subpanel-title">
              <Zap size={11} />
              Case timeline ({evidence.length} touch{evidence.length === 1 ? "" : "es"})
            </div>

            <div className="case-timeline">
              {evidence.map((e) => {
                const confMeta = e.attributionConfidence && CONFIDENCE_META[e.attributionConfidence];
                return (
                  <div key={e.id} className="case-timeline-row">
                    <span className="case-timeline-time">{e.time}</span>
                    <span className={`confidence-dot ${confMeta ? confMeta.className : "confidence-unknown"}`} />
                    <span className={`case-timeline-sev sev-${e.severityRaw || "info"}`}>{e.type}</span>
                    <span className="case-timeline-resource">{e.resource}</span>
                    <span className="case-timeline-touch">{e.touchCount ?? "—"} touches</span>

                    {warningCrossedAt?.id === e.id && (
                      <span className="case-timeline-flag flag-warning">Warning threshold crossed</span>
                    )}
                    {criticalCrossedAt?.id === e.id && (
                      <span className="case-timeline-flag flag-critical">Critical threshold crossed</span>
                    )}
                  </div>
                );
              })}

              {incident.escalated && (
                <div className="case-timeline-row case-timeline-escalation">
                  <span className="case-timeline-flag flag-critical">
                    <Zap size={9} /> Auto-escalated to kill after repeat post-suspend activity
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="threshold-panel">
        <div className="threshold-panel-title">
          Touch thresholds
          <span>Fires warning / critical after N touches within the detection window</span>
        </div>

        <div className="slider-row">
          <label>Warning</label>
          <input
            type="range"
            min="1"
            max="15"
            value={local.warning}
            onChange={(e) => setLocal({ ...local, warning: Number(e.target.value) })}
            onMouseUp={(e) => commit({ ...local, warning: Number(e.target.value) })}
            onTouchEnd={(e) => commit({ ...local, warning: Number(e.target.value) })}
            onKeyUp={(e) => commit({ ...local, warning: Number(e.target.value) })}
          />
          <output>{local.warning}</output>
        </div>

        <div className="slider-row critical">
          <label>Critical</label>
          <input
            type="range"
            min="2"
            max="20"
            value={local.critical}
            onChange={(e) => setLocal({ ...local, critical: Number(e.target.value) })}
            onMouseUp={(e) => commit({ ...local, critical: Number(e.target.value) })}
            onTouchEnd={(e) => commit({ ...local, critical: Number(e.target.value) })}
            onKeyUp={(e) => commit({ ...local, critical: Number(e.target.value) })}
          />
          <output>{local.critical}</output>
        </div>

        <div className="threshold-preview">
          <span>
            With these thresholds, past events would show <strong>{wouldWarn}</strong> warning
            and <strong>{wouldEscalate}</strong> critical.
          </span>
        </div>

        {thresholdUpdateError && <div className="threshold-error">{thresholdUpdateError}</div>}
      </div>

      <div className="detection-engine-stats">
        <div className="detection-subpanel-title">
          <ShieldCheck size={11} />
          Detection engine — attribution & technique mix (all events)
        </div>

        <div className="analysis-stats-row no-border">
          <div className="analysis-stat-block">
            <span className="analysis-stat-label">Attribution</span>
            <div className="analysis-stat-chips">
              <span className="confidence-chip confidence-high">{globalConfidence.high} high</span>
              <span className="confidence-chip confidence-ambiguous">{globalConfidence.ambiguous} ambiguous</span>
              <span className="confidence-chip confidence-unknown">{globalConfidence.unknown} unknown</span>
            </div>
          </div>

          {globalTechniques.length > 0 && (
            <div className="analysis-stat-block">
              <span className="analysis-stat-label">Techniques</span>
              <div className="analysis-stat-chips">
                {globalTechniques.map(([id, count]) => (
                  <span key={id} className="technique-chip" title={MITRE_LABELS[id] || id}>
                    {id} <em>{MITRE_LABELS[id] || "Unknown"}</em>
                    <b>{count}</b>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
