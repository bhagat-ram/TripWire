import { useState } from "react";

import { Sidebar } from "./components/layout/Sidebar";
import { Topbar } from "./components/layout/Topbar";
import { OverviewCards } from "./components/common/OverviewCards";
import { ActivityFeed } from "./components/activity/ActivityFeed";
import { IncidentQueue } from "./components/incidents/IncidentQueue";
import { DetectionPanel } from "./components/threat/DetectionPanel";
import { ResponseBar } from "./components/response/ResponseBar";
import { InvestigationDrawer } from "./components/modals/InvestigationDrawer";
import { SettingsModal } from "./components/modals/SettingsModal";
import { FolderTreeDiagram } from "./components/analysis/FolderTreeDiagram";

import { useTripwireConnection } from "./hooks/useTripwireConnection";
import { DECOY_CATEGORIES, categoryMatches } from "./data/decoyResources";

function App() {
  const {
    events,
    incidents,
    selectedIncidentId,
    selectIncident,
    backendConnected,
    health,
    thresholds,
    thresholdUpdateError,
    autoResponseRules,
    escalateAfterTouches,
    autoResponseUpdateError,
    autoResponsePending,
    applyAutoResponse,
    dryRunPending,
    lastArrivedId,
    lastActionResult,
    triggerSimulation,
    stopSimulation,
    simulationRunning,
    simulationError,
    clearSimulation,
    respondToIncident,
    addIncidentNote,
    removeIncident,
    clearResolved,
    removeEvent,
    clearAllEvents,
    applyThresholds,
    setDryRun,
  } = useTripwireConnection();

  const [selectedCategoryId, setSelectedCategoryId] = useState("all");
  const [focusEvent, setFocusEvent] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState(null); // null | "warning" | "critical"
  const [density, setDensity] = useState("comfortable"); // "comfortable" | "compact"

  const selectedCategory =
    DECOY_CATEGORIES.find((c) => c.id === selectedCategoryId) || DECOY_CATEGORIES[0];

  const filteredEvents = events
    .filter((event) => categoryMatches(selectedCategory, event.resource))
    .filter((event) => !severityFilter || event.severityRaw === severityFilter);

  const selectedIncident = incidents.find((inc) => inc.id === selectedIncidentId) || null;
  const drawerIncident = incidents.find((inc) => inc.id === focusEvent?.incidentId) || selectedIncident;

  const hasOpenCase = incidents.some((inc) => inc.status === "open" || inc.status === "escalated");
  const openCaseCount = incidents.filter(
    (inc) => inc.status === "open" || inc.status === "escalated"
  ).length;
  const hasCriticalOpen = incidents.some(
    (inc) => inc.severity === "Critical" && (inc.status === "open" || inc.status === "escalated")
  );
  const allContainedOrDismissed =
    incidents.length > 0 && incidents.every((inc) => inc.status === "contained" || inc.status === "dismissed");

  const posture = !hasOpenCase
    ? allContainedOrDismissed
      ? "watching"
      : "safe"
    : hasCriticalOpen
    ? "critical"
    : "warning";

  const toggleSeverityFilter = (sev) =>
    setSeverityFilter((prev) => (prev === sev ? null : sev));

  const openEventInDrawer = (event) => {
    const owningIncident = incidents.find((inc) => inc.eventIds.includes(event.id));
    setFocusEvent(owningIncident ? { ...event, incidentId: owningIncident.id } : event);
    if (owningIncident) selectIncident(owningIncident.id);
    setDrawerOpen(true);
  };

  const openIncidentInDrawer = (incidentId) => {
    selectIncident(incidentId);
    setFocusEvent(null);
    setDrawerOpen(true);
  };

  return (
    <div className="app-shell">
      <Sidebar
        events={events}
        selectedCategoryId={selectedCategoryId}
        onSelectCategory={setSelectedCategoryId}
        backendConnected={backendConnected}
        health={health}
        hasOpenCase={hasOpenCase}
        allContainedOrDismissed={allContainedOrDismissed}
        openCaseCount={openCaseCount}
        onOpenSettings={() => setSettingsOpen(true)}
      />

      <main className="main-content">
        <Topbar
          hasOpenCase={hasOpenCase}
          allContainedOrDismissed={allContainedOrDismissed}
          posture={posture}
          health={health}
          dryRunPending={dryRunPending}
          onSetDryRun={setDryRun}
          onOpenSettings={() => setSettingsOpen(true)}
        />

        <div id="section-overview">
          <OverviewCards
            events={events}
            incidents={incidents}
            severityFilter={severityFilter}
            onToggleSeverityFilter={toggleSeverityFilter}
            lastArrivedId={lastArrivedId}
          />
        </div>

        <div id="section-activity">
          <ActivityFeed
            filteredEvents={filteredEvents}
            focusEventId={focusEvent?.id}
            onSelectEvent={openEventInDrawer}
            onSimulate={triggerSimulation}
            onStopSimulate={stopSimulation}
            simulationRunning={simulationRunning}
            simulationError={simulationError}
            onReset={clearSimulation}
            onRemoveEvent={removeEvent}
            onClearAllEvents={clearAllEvents}
            severityFilter={severityFilter}
            onToggleSeverityFilter={toggleSeverityFilter}
            density={density}
            onSetDensity={setDensity}
            lastArrivedId={lastArrivedId}
          />
        </div>

        <div id="section-analysis">
          <FolderTreeDiagram events={events} lastArrivedId={lastArrivedId} onSelectEvent={openEventInDrawer} />
        </div>

        <div id="section-incidents">
          <IncidentQueue
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelect={openIncidentInDrawer}
            onRemove={removeIncident}
            onClearResolved={clearResolved}
          />
        </div>

        <div id="section-detection">
          <DetectionPanel
            incident={selectedIncident}
            events={events}
            thresholds={thresholds}
            thresholdUpdateError={thresholdUpdateError}
            onApplyThresholds={applyThresholds}
          />
        </div>

        <div id="section-response">
          <ResponseBar
            incident={selectedIncident}
            events={events}
            onRespond={respondToIncident}
            lastActionResult={lastActionResult}
            health={health}
          />
        </div>

        <SettingsModal
          open={settingsOpen}
          onClose={() => setSettingsOpen(false)}
          rules={autoResponseRules}
          escalateAfterTouches={escalateAfterTouches}
          onApply={applyAutoResponse}
          updateError={autoResponseUpdateError}
          pending={autoResponsePending}
        />

        {drawerOpen && (
          <InvestigationDrawer
            incident={drawerIncident}
            focusEvent={focusEvent}
            allEvents={events}
            onClose={() => setDrawerOpen(false)}
            onRespond={respondToIncident}
            onAddNote={addIncidentNote}
          />
        )}
      </main>
    </div>
  );
}

export default App;
