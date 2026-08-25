import { Sparkles } from "lucide-react";
import { DetectionPanel } from "./DetectionPanel";

/**
 * Detection — promoted from a scroll-spy section to its own routed page.
 * DetectionPanel (attribution status card + threshold sliders) is
 * unchanged; this wrapper just gives it a page header consistent with
 * Analysis/Incidents. Still driven by the same `selectedIncident` state
 * App.jsx already tracks, so picking a case on the Incidents page and then
 * navigating here shows that case's detection status, same as before when
 * they were both sections on one page.
 *
 * AI-tuning badge: placeholder only — see AnalysisPage's docstring for the
 * product decision to scope AI integration out of this pass. This is
 * likely where "suggest a warning/critical threshold from recent activity"
 * would live later.
 */
export function DetectionPage({ incident, events, thresholds, thresholdUpdateError, onApplyThresholds }) {
  return (
    <div className="page-view">
      <div className="page-header">
        <div>
          <h1>Detection</h1>
          <p>Attribution status and tunable thresholds for the selected case.</p>
        </div>
        <span className="ai-soon-badge" title="AI-suggested thresholds — planned, not built yet">
          <Sparkles size={11} />
          AI tuning · coming soon
        </span>
      </div>

      <DetectionPanel
        incident={incident}
        events={events}
        thresholds={thresholds}
        thresholdUpdateError={thresholdUpdateError}
        onApplyThresholds={onApplyThresholds}
      />
    </div>
  );
}
