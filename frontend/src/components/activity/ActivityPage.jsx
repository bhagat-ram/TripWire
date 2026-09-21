import { ActivityFeed } from "./ActivityFeed";

/**
 * Live activity — routed page (SidebarNav's SECTIONS: `type: "page"`).
 * Used to be a scroll-jump section on the one-page dashboard, which made it
 * feel identical to Overview (both visible in the same short scroll on most
 * screens). Pulled out into its own page — like Settings — so it reads as
 * a distinct screen instead of an anchor a few hundred pixels down.
 */
export function ActivityPage({
  filteredEvents,
  focusEventId,
  onSelectEvent,
  onSimulate,
  onStopSimulate,
  simulationRunning,
  simulationError,
  onReset,
  onRemoveEvent,
  onClearAllEvents,
  severityFilter,
  onToggleSeverityFilter,
  density,
  onSetDensity,
  lastArrivedId,
}) {
  return (
    <div className="page-view">
      <div className="page-header">
        <div>
          <h1>Live activity</h1>
          <p>Every touch of a protected resource, in real time — as a timeline or grouped by process.</p>
        </div>
      </div>

      <ActivityFeed
        filteredEvents={filteredEvents}
        focusEventId={focusEventId}
        onSelectEvent={onSelectEvent}
        onSimulate={onSimulate}
        onStopSimulate={onStopSimulate}
        simulationRunning={simulationRunning}
        simulationError={simulationError}
        onReset={onReset}
        onRemoveEvent={onRemoveEvent}
        onClearAllEvents={onClearAllEvents}
        severityFilter={severityFilter}
        onToggleSeverityFilter={onToggleSeverityFilter}
        density={density}
        onSetDensity={onSetDensity}
        lastArrivedId={lastArrivedId}
      />
    </div>
  );
}
