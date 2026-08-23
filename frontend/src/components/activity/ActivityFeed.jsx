import { useEffect, useState } from "react";
import { AlertTriangle, RefreshCw, Radar, ChevronLeft, ChevronRight } from "lucide-react";
import { EventRow } from "./EventRow";

const PAGE_SIZE_OPTIONS = [10, 25, 50];

export function ActivityFeed({
  filteredEvents,
  focusEventId,
  onSelectEvent,
  onSimulate,
  onReset,
  onRemoveEvent,
  severityFilter,
  onToggleSeverityFilter,
  density,
  onSetDensity,
  lastArrivedId,
}) {
  const [pageSize, setPageSize] = useState(PAGE_SIZE_OPTIONS[0]);
  const [page, setPage] = useState(1);

  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));

  // Live events prepend to the top of the array as they arrive, so page 1
  // always has the newest activity — no need to reset there. But a filter
  // change (severity chip, category) can shrink the list out from under
  // whatever page you were on, so clamp back into range instead of just
  // going blank.
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [totalPages, page]);

  // Jumping filters (severity chip) should feel like a fresh view.
  useEffect(() => {
    setPage(1);
  }, [severityFilter]);

  const startIdx = (page - 1) * pageSize;
  const pageEvents = filteredEvents.slice(startIdx, startIdx + pageSize);
  const rangeStart = filteredEvents.length === 0 ? 0 : startIdx + 1;
  const rangeEnd = Math.min(startIdx + pageSize, filteredEvents.length);

  return (
    <section className="activity-section">
      <div className="section-heading">
        <div>
          <h2>Recent activity</h2>
          <p>Events will appear here as they are detected.</p>
        </div>

        <div className="activity-controls">
          <div className="severity-filters">
            <button
              className={`severity-chip ${severityFilter === "warning" ? "active warning" : ""}`}
              onClick={() => onToggleSeverityFilter("warning")}
            >
              Warning
            </button>
            <button
              className={`severity-chip ${severityFilter === "critical" ? "active critical" : ""}`}
              onClick={() => onToggleSeverityFilter("critical")}
            >
              Critical
            </button>
          </div>

          <div className="density-toggle">
            <button
              className={density === "comfortable" ? "active" : ""}
              onClick={() => onSetDensity("comfortable")}
            >
              Comfortable
            </button>
            <button
              className={density === "compact" ? "active" : ""}
              onClick={() => onSetDensity("compact")}
            >
              Compact
            </button>
          </div>

          <button className="simulation-button" onClick={onSimulate}>
            <AlertTriangle size={12} />
            Simulate detection
          </button>

          <button
            className="filter-button"
            onClick={() => {
              onReset();
              setPage(1);
            }}
          >
            <RefreshCw size={12} />
            Reset
          </button>
        </div>
      </div>

      <div className="activity-card">
        <div className="activity-table-header">
          <span>Event</span>
          <span>Resource</span>
          <span>Process</span>
          <span>Time</span>
          <span />
        </div>

        {filteredEvents.length === 0 ? (
          <div className="empty-activity">
            <div className="empty-symbol">
              <Radar size={19} />
            </div>
            <h3>No activity yet</h3>
            <p>
              Tripwire is watching every protected resource.
              <br />
              Detected touches will appear here in real time.
            </p>
          </div>
        ) : (
          <>
            <div className="event-list">
              {pageEvents.map((event) => (
                <EventRow
                  key={event.id}
                  event={event}
                  isSelected={focusEventId === event.id}
                  onSelect={onSelectEvent}
                  onRemove={onRemoveEvent}
                  density={density}
                  isNew={event.id === lastArrivedId}
                />
              ))}
            </div>

            <div className="activity-pagination">
              <span className="pagination-range">
                {rangeStart}–{rangeEnd} of {filteredEvents.length}
              </span>

              <div className="pagination-size">
                {PAGE_SIZE_OPTIONS.map((size) => (
                  <button
                    key={size}
                    className={pageSize === size ? "active" : ""}
                    onClick={() => {
                      setPageSize(size);
                      setPage(1);
                    }}
                  >
                    {size}
                  </button>
                ))}
              </div>

              <div className="pagination-controls">
                <button
                  className="pagination-nav"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  aria-label="Previous page"
                >
                  <ChevronLeft size={12} />
                </button>
                <span className="pagination-page">
                  Page {page} of {totalPages}
                </span>
                <button
                  className="pagination-nav"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  aria-label="Next page"
                >
                  <ChevronRight size={12} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
