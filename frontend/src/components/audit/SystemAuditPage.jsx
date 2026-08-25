import { useEffect, useState } from "react";
import { Eye, ScanEye, ChevronLeft, ChevronRight } from "lucide-react";

const PAGE_SIZE_OPTIONS = [10, 25, 50];

/**
 * System Audit — the optional full-system fanotify feed (fanotify_watcher.py
 * / server.py's /fs-audit + "fs_open"), separate from the decoy-only
 * Activity page. This is every file *write* on the marked mount(s), by any
 * process, with no severity/attribution/classification attached — see
 * fanotify_watcher.py's module docstring for why it deliberately never
 * touches the classifier/panic pipeline. It's a raw audit trail for manual
 * review/correlation, not another detection surface.
 *
 * Requires Linux + root; starting it can fail for completely ordinary
 * reasons (wrong OS, not root, kernel too old), surfaced inline via
 * fsMonitorUpdateError / health.fs_monitor_error rather than as a crash.
 */
export function SystemAuditPage({ events, health, fsMonitorPending, fsMonitorUpdateError, onSetFullSystemMonitor }) {
  const [pageSize, setPageSize] = useState(PAGE_SIZE_OPTIONS[0]);
  const [page, setPage] = useState(1);

  const alive = !!health?.fs_monitor_alive;
  const requested = !!health?.fs_monitor_requested;
  const mounts = health?.fs_monitor_mounts || [];
  const backendError = health?.fs_monitor_error;

  const totalPages = Math.max(1, Math.ceil(events.length / pageSize));

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [totalPages, page]);

  const startIdx = (page - 1) * pageSize;
  const pageEvents = events.slice(startIdx, startIdx + pageSize);
  const rangeStart = events.length === 0 ? 0 : startIdx + 1;
  const rangeEnd = Math.min(startIdx + pageSize, events.length);

  const statusLine = !requested
    ? "Off — every file write on protected mounts, not just decoy touches, will be logged here once enabled."
    : alive
    ? mounts.length
      ? `Watching ${mounts.join(", ")}`
      : "Watching"
    : backendError
    ? backendError
    : "Starting…";

  return (
    <section className="activity-section">
      <div className="section-heading">
        <div>
          <h2>System audit</h2>
          <p>Raw file-write activity across the filesystem — not classified, not scored, logged only.</p>
        </div>

        <div className="activity-controls">
          <button
            className={`dryrun-pill fs-monitor-pill ${alive ? "live" : ""}`}
            onClick={() => onSetFullSystemMonitor(!requested)}
            disabled={fsMonitorPending}
            title={alive ? "Click to stop the full-system watcher" : "Click to start the full-system watcher"}
          >
            <ScanEye size={11} />
            {alive ? "Watching" : requested ? "Starting…" : "Off"}
          </button>
        </div>
      </div>

      <div className={`fs-monitor-status ${alive ? "" : requested && backendError ? "fs-monitor-status-error" : ""}`}>
        {statusLine}
      </div>
      {fsMonitorUpdateError && <div className="fs-monitor-status fs-monitor-status-error">{fsMonitorUpdateError}</div>}

      <div className="activity-card">
        <div className="activity-table-header fs-audit-table-header">
          <span>Process</span>
          <span>PID</span>
          <span>File opened</span>
          <span>Executable</span>
          <span>Time</span>
        </div>

        {events.length === 0 ? (
          <div className="empty-activity">
            <div className="empty-symbol">
              <Eye size={19} />
            </div>
            <h3>No audit activity yet</h3>
            <p>
              {alive
                ? "Watching — file-write events across the marked mount(s) will appear here as they happen."
                : "Enable the full-system watcher above to start logging every file open, not just decoy touches."}
            </p>
          </div>
        ) : (
          <>
            <div className="event-list">
              {pageEvents.map((event) => (
                <div className="event-row fs-audit-row" key={event.id}>
                  <span className="event-process">{event.process}</span>
                  <span className="event-time">{event.pid}</span>
                  <span className="event-resource">{event.resource}</span>
                  <span className="event-resource fs-audit-exe">{event.exePath || "—"}</span>
                  <span className="event-time">{event.time}</span>
                </div>
              ))}
            </div>

            <div className="activity-pagination">
              <span className="pagination-range">
                {rangeStart}–{rangeEnd} of {events.length}
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
