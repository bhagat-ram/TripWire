/**
 * incidentReport.js
 *
 * Turns an incident case + its evidence events into a Markdown report and
 * triggers a browser download. This is the one "response" action that has
 * nothing to do with the honeypot backend — it's pure client-side
 * summarization, so it always works even in demo mode or while the backend
 * is disconnected.
 */

function line(label, value) {
  return `| ${label} | ${value ?? "—"} |`;
}

export function buildIncidentReportMarkdown(incident, events) {
  const evidence = events.filter((e) => incident.eventIds.includes(e.id));

  const header = `# Incident report — ${incident.title}\n\nGenerated ${new Date().toLocaleString()}\n`;

  const summary = [
    "## Summary",
    "",
    "| Field | Value |",
    "| --- | --- |",
    line("Status", incident.status),
    line("Severity", incident.severity),
    line("Process", incident.process),
    line("PID", incident.pid),
    line("Parent process", incident.parentProcess ? `${incident.parentProcess} (PID ${incident.parentPid})` : null),
    line("MITRE ATT&CK", incident.mitre),
    line("First seen", incident.firstSeen),
    line("Last seen", incident.lastSeen),
    line("Evidence events", evidence.length),
    "",
  ].join("\n");

  const evidenceSection = [
    "## Evidence timeline",
    "",
    "| Time | Action | Resource | Severity | Touch # |",
    "| --- | --- | --- | --- | --- |",
    ...evidence.map((e) => `| ${e.time} | ${e.type} | ${e.resource} | ${e.severity} | ${e.touchCount ?? "—"} |`),
    "",
  ].join("\n");

  const actionSection = [
    "## Response actions taken",
    "",
    incident.actionLog.length
      ? [
          "| Time | Action | Before | After |",
          "| --- | --- | --- | --- |",
          ...incident.actionLog.map(
            (a) => `| ${a.ts} | ${a.label}${a.dryRun ? " (dry run)" : ""} | ${a.before} | ${a.after} |`
          ),
        ].join("\n")
      : "_No response actions taken yet._",
    "",
  ].join("\n");

  const notesSection = [
    "## Analyst notes",
    "",
    incident.notes.length
      ? incident.notes.map((n) => `- **${n.ts}** — ${n.text}`).join("\n")
      : "_No analyst notes recorded._",
    "",
  ].join("\n");

  return [header, summary, evidenceSection, actionSection, notesSection].join("\n");
}

/** Builds the report and triggers a browser download of it as a .md file. */
export function downloadIncidentReport(incident, events) {
  const markdown = buildIncidentReportMarkdown(incident, events);
  const blob = new Blob([markdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `incident-report-${incident.id}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
