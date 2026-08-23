import { AlertTriangle, Flame, FileText, X } from "lucide-react";

export function EventRow({ event, isSelected, onSelect, onRemove, density, isNew }) {
  const severityClass =
    event.severity === "Critical"
      ? "event-critical"
      : event.severity === "Warning"
      ? "event-warning"
      : "";

  const Icon =
    event.severity === "Critical" ? Flame : event.severity === "Warning" ? AlertTriangle : FileText;

  return (
    <div
      className={`event-row ${severityClass} ${isSelected ? "event-selected" : ""} ${
        density === "compact" ? "compact" : ""
      } ${isNew ? "event-new" : ""}`}
      onClick={() => onSelect(event)}
    >
      <div className="event-type">
        <Icon size={12} />
        <span>{event.type}</span>
      </div>

      <span className="event-resource">{event.resource}</span>
      <span className="event-process">{event.process}</span>
      <span className="event-time">{event.time}</span>

      {onRemove && (
        <button
          className="event-row-remove"
          onClick={(e) => {
            e.stopPropagation();
            onRemove(event.id);
          }}
          title="Remove this event from the feed"
          aria-label="Remove event"
        >
          <X size={11} />
        </button>
      )}
    </div>
  );
}
