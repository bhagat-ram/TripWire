import React, { useEffect, useMemo, useState } from "react";
import { Trash2, ChevronLeft, ChevronRight } from "lucide-react";

const PAGE_SIZE_OPTIONS = [10, 25, 50];

// Canonical actions this feed can ever contain — fanotify_watcher.py
// computes these identically whether the running backend is fanotify or
// the inotify fallback (see FileOpenEvent.action / _fallback_event), so
// the UI can treat both sources exactly the same way. "created" never
// actually occurs: a new file's first write still arrives as a close-after-
// write and is reported as "modified", so no bucket is faked for it.
const ACTION_META = {
  modified: {
    label: "MODIFIED",
    icon: "✎",
    dot: "bg-[var(--safe-dot)]",
    chip: "border-[var(--safe-dim)] bg-[var(--safe-dim)] text-[var(--safe-dot)]",
    accent: "bg-[var(--safe-dot)]",
  },
  deleted: {
    label: "DELETED",
    icon: "×",
    dot: "bg-[var(--accent-critical)]",
    chip: "border-[var(--accent-critical-border)] bg-[var(--accent-critical-dim)] text-[var(--accent-critical)]",
    accent: "bg-[var(--accent-critical)]",
  },
  renamed: {
    label: "RENAMED / MOVED",
    icon: "↗",
    dot: "bg-[var(--accent-warning)]",
    chip: "border-[var(--accent-warning-border)] bg-[var(--accent-warning-dim)] text-[var(--accent-warning)]",
    accent: "bg-[var(--accent-warning)]",
  },
};

function formatTime(event) {
  // mapFsOpenEvent already formats this as a locale time string — fall
  // back to formatting a raw ts/timestamp only if an older cached shape
  // sneaks in.
  if (event?.time) return event.time;
  const raw = event?.ts ?? event?.timestamp;
  if (!raw) return "—";
  const date = typeof raw === "number" ? new Date(raw * 1000) : new Date(raw);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function FileActivityRow({ event, index }) {
  const action = ACTION_META[event?.action] ? event.action : "modified";
  const meta = ACTION_META[action];

  const path = event?.resource || "Unknown file";
  const filename = event?.filename || path.split(/[\\/]/).filter(Boolean).pop() || "Unknown file";
  const processName = event?.process || "unknown";
  const pidUnavailable = Boolean(event?.pidUnavailable);
  const pidDisplay = pidUnavailable ? "unavailable" : event?.pid ?? "—";

  return (
    <div
      className="relative grid grid-cols-[3px_1fr] overflow-hidden rounded-[7px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] [animation:audit-row-in_0.2s_ease_both]"
      style={{ animationDelay: `${Math.min(index, 40) * 20}ms` }}
    >
      <div className={meta.accent} />

      <div className="min-w-0 p-[10px_12px]">
        <div className="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
          <div className="flex min-w-0 items-start gap-2.5">
            <span
              className={`mt-px flex h-4 w-4 flex-none items-center justify-center rounded-[4px] border text-[10px] font-bold ${meta.chip}`}
            >
              {meta.icon}
            </span>

            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-[7px] font-bold tracking-[0.06em]" style={{ color: `var(${action === "deleted" ? "--accent-critical" : action === "renamed" ? "--accent-warning" : "--safe-dot"})` }}>
                  {meta.label}
                </span>
              </div>

              <div className="mt-0.5 truncate text-[9px] font-medium text-[var(--text-primary)]">
                {filename}
              </div>

              <div className="mt-0.5 truncate font-[var(--font-mono)] text-[7px] text-[var(--text-tertiary)]" title={path}>
                {path}
              </div>
            </div>
          </div>

          <time className="flex-none whitespace-nowrap font-[var(--font-mono)] text-[7px] text-[var(--text-quiet)] sm:pl-0" style={{ paddingLeft: "26px" }}>
            {formatTime(event)}
          </time>
        </div>

        <div className="mt-2 flex flex-wrap gap-1.5">
          <div className="flex items-center gap-1.5 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-inset)] px-[7px] py-[3px]">
            <span className="text-[6px] font-bold uppercase tracking-[0.06em] text-[var(--text-quiet)]">Process</span>
            <span className="truncate text-[7px] text-[var(--text-secondary)]">{processName}</span>
          </div>

          <div className="flex items-center gap-1.5 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-inset)] px-[7px] py-[3px]">
            <span className="text-[6px] font-bold uppercase tracking-[0.06em] text-[var(--text-quiet)]">PID</span>
            <span
              className={`font-[var(--font-mono)] text-[7px] ${
                pidUnavailable ? "italic text-[var(--text-quiet)]" : "text-[var(--text-secondary)]"
              }`}
            >
              {pidDisplay}
            </span>
          </div>

          {event?.exePath && (
            <div className="flex min-w-0 flex-1 basis-[220px] items-center gap-1.5 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-inset)] px-[7px] py-[3px]">
              <span className="flex-none text-[6px] font-bold uppercase tracking-[0.06em] text-[var(--text-quiet)]">Executable</span>
              <span className="truncate font-[var(--font-mono)] text-[7px] text-[var(--text-secondary)]" title={event.exePath}>
                {event.exePath}
              </span>
            </div>
          )}

          {pidUnavailable && !event?.exePath && (
            <div className="flex items-center gap-1.5 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-inset)] px-[7px] py-[3px]">
              <span className="text-[7px] italic text-[var(--text-quiet)]">
                Process attribution unavailable on this backend (inotify)
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * SystemAuditPage — full-system fanotify/inotify open()-audit feed.
 * Deliberately styled to match the rest of the "daylight ops room" console
 * (see index.css design tokens) rather than a standalone dark theme, since
 * this is one page in the same dashboard, not a separate product.
 */
export function SystemAuditPage({
  events = [],
  health,
  fsMonitorPending = false,
  fsMonitorUpdateError = null,
  onSetFullSystemMonitor,
  onClear,
}) {
  const [pageSize, setPageSize] = useState(PAGE_SIZE_OPTIONS[0]);
  const [page, setPage] = useState(1);

  const totalPages = Math.max(1, Math.ceil(events.length / pageSize));

  // Live rows prepend to the top as they arrive, so page 1 always shows the
  // newest activity — no need to reset there. But clearing the feed (or the
  // buffer shrinking under a page size change) can leave `page` pointing
  // past the end, so clamp back into range instead of rendering blank.
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [totalPages, page]);

  const startIdx = (page - 1) * pageSize;
  const pageEvents = events.slice(startIdx, startIdx + pageSize);
  const rangeStart = events.length === 0 ? 0 : startIdx + 1;
  const rangeEnd = Math.min(startIdx + pageSize, events.length);

  const monitorAlive = Boolean(health?.fs_monitor_alive);
  const monitorRequested = Boolean(health?.fs_monitor_requested);
  const monitorBackend = health?.fs_monitor_backend || null; // "fanotify" | "inotify" | null
  const monitorMounts = health?.fs_monitor_mounts || [];
  // An in-flight toggle failure (e.g. "Backend unreachable.") is more
  // immediately relevant than the last-known /health error, which may be
  // stale or may not exist yet on a backend that predates this field.
  const monitorError = fsMonitorUpdateError || health?.fs_monitor_error || null;

  const statusLabel = monitorAlive
    ? `LIVE — ${monitorBackend ? monitorBackend.toUpperCase() : "UNKNOWN BACKEND"}`
    : monitorRequested
    ? "STARTING…"
    : "MONITOR OFF";

  const stats = useMemo(() => {
    const counts = { modified: 0, deleted: 0, renamed: 0 };
    events.forEach((event) => {
      const action = ACTION_META[event?.action] ? event.action : "modified";
      counts[action]++;
    });
    return counts;
  }, [events]);

  const handleToggle = () => {
    if (!onSetFullSystemMonitor || fsMonitorPending) return;
    onSetFullSystemMonitor(!monitorRequested);
  };

  return (
    <div>
      <style>{`
        @keyframes audit-row-in {
          from { opacity: 0; transform: translateY(4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <header className="mb-3.5 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-[7px] font-bold uppercase tracking-[0.08em] text-[var(--text-tertiary)]">
            <span
              className={`h-[5px] w-[5px] rounded-full ${
                monitorAlive
                  ? "bg-[var(--safe-dot)] shadow-[0_0_0_3px_var(--safe-dim)]"
                  : monitorRequested
                  ? "bg-[var(--accent-warning)] shadow-[0_0_0_3px_var(--accent-warning-dim)]"
                  : "bg-[var(--text-quiet)]"
              }`}
            />
            FULL SYSTEM AUDIT / {statusLabel}
          </div>

          <h1 className="m-0 text-[17px] font-bold tracking-[-0.01em] text-[var(--text-primary)]">
            System Activity
          </h1>

          <p className="mt-[3px] max-w-[480px] text-[8px] leading-relaxed text-[var(--text-tertiary)]">
            Real filesystem manipulation events detected by TripWire's full-system watcher. Read-only file
            access is intentionally excluded — only writes, deletes, and renames/moves ever appear here,
            regardless of whether fanotify or the inotify fallback is running underneath.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {monitorMounts.length > 0 && (
            <div className="flex items-center gap-1 rounded-[14px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-[9px] py-[5px] text-[7px] text-[var(--text-secondary)]">
              <span className="font-[var(--font-mono)]">{monitorMounts.join(", ")}</span>
            </div>
          )}

          {onSetFullSystemMonitor && (
            <button
              type="button"
              onClick={handleToggle}
              disabled={fsMonitorPending}
              aria-pressed={monitorRequested}
              className={`flex items-center gap-1.5 rounded-[14px] border px-[9px] py-[5px] text-[8px] font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                monitorRequested
                  ? "border-[var(--accent-critical-border)] bg-[var(--accent-critical-dim)] text-[var(--accent-critical)]"
                  : "border-[var(--border-strong)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
              }`}
            >
              <span
                className={`h-[5px] w-[5px] rounded-full ${
                  monitorRequested ? "bg-[var(--accent-critical)]" : "bg-[var(--text-quiet)]"
                }`}
              />
              {fsMonitorPending ? "UPDATING…" : monitorRequested ? "MONITOR ON" : "MONITOR OFF"}
            </button>
          )}

          {onClear && (
            <button
              type="button"
              onClick={() => {
                onClear();
                setPage(1);
              }}
              disabled={events.length === 0}
              title="Clear every row from the audit feed only — the monitor keeps running"
              className="flex items-center gap-1.5 rounded-[6px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-[9px] py-[5px] text-[8px] font-semibold text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-[var(--bg-surface)] disabled:hover:text-[var(--text-secondary)]"
            >
              <Trash2 size={11} />
              Clear activity
            </button>
          )}
        </div>
      </header>

      {monitorError && (
        <div className="mb-3.5 flex items-center gap-1.5 rounded-[7px] border border-[var(--accent-warning-border)] bg-[var(--accent-warning-dim)] px-[10px] py-[7px] text-[8px] font-medium text-[var(--accent-warning)]">
          {monitorError}
        </div>
      )}

      <section className="mb-3.5 grid grid-cols-3 gap-[9px]">
        {[
          ["MODIFIED", stats.modified, "--safe-dot"],
          ["DELETED", stats.deleted, "--accent-critical"],
          ["RENAMED", stats.renamed, "--accent-warning"],
        ].map(([label, value, color]) => (
          <div
            key={label}
            className="rounded-[7px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-3"
          >
            <div className="text-[8px] font-bold uppercase tracking-[0.08em] text-[var(--text-tertiary)]">
              {label}
            </div>
            <div
              className="mt-1 font-[var(--font-mono)] text-[17px] font-semibold"
              style={{ color: `var(${color})` }}
            >
              {value}
            </div>
          </div>
        ))}
      </section>

      <section className="flex flex-col gap-1.5">
        {events.length === 0 ? (
          <div className="flex min-h-[190px] flex-col items-center justify-center rounded-[7px] border border-dashed border-[var(--border-strong)] bg-[var(--bg-surface)] text-center">
            <div className="mb-2 flex h-[34px] w-[34px] items-center justify-center rounded-full border border-[var(--border-strong)] text-[var(--text-quiet)]">
              ⌁
            </div>
            <h3 className="m-0 text-[9px] font-semibold text-[var(--text-secondary)]">
              {monitorAlive ? "No filesystem activity yet" : "Full-system monitor is off"}
            </h3>
            <p className="mx-auto mt-[5px] max-w-[220px] text-[7px] leading-relaxed text-[var(--text-quiet)]">
              {monitorAlive
                ? "Genuine modifications, deletions, and renames/moves will appear here as they happen."
                : "Turn on the monitor above to start recording real filesystem writes, deletes, and renames."}
            </p>
          </div>
        ) : (
          <>
            {pageEvents.map((event, index) => (
              <FileActivityRow key={event?.id || `${event?.receivedAt || Date.now()}-${index}`} event={event} index={index} />
            ))}

            <div className="mt-1 flex items-center justify-between gap-2.5 rounded-[7px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-[10px] py-[7px]">
              <span className="whitespace-nowrap text-[7px] text-[var(--text-quiet)]">
                {rangeStart}–{rangeEnd} of {events.length}
              </span>

              <div className="flex items-center gap-0.5 overflow-hidden rounded-[6px] border border-[var(--border-strong)]">
                {PAGE_SIZE_OPTIONS.map((size) => (
                  <button
                    key={size}
                    type="button"
                    onClick={() => {
                      setPageSize(size);
                      setPage(1);
                    }}
                    className={`h-5 min-w-[22px] border-r border-[var(--border-strong)] px-[6px] text-[7px] font-semibold last:border-r-0 ${
                      pageSize === size
                        ? "bg-[var(--bg-raised)] text-[var(--text-primary)]"
                        : "bg-[var(--bg-surface)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    {size}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  aria-label="Previous page"
                  className="flex h-5 w-5 items-center justify-center rounded-[5px] border border-[var(--border-strong)] bg-[var(--bg-surface)] text-[var(--text-secondary)] transition-colors hover:enabled:bg-[var(--bg-hover)] hover:enabled:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-35"
                >
                  <ChevronLeft size={11} />
                </button>
                <span className="min-w-[68px] whitespace-nowrap text-center text-[7px] font-semibold text-[var(--text-tertiary)]">
                  Page {page} of {totalPages}
                </span>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  aria-label="Next page"
                  className="flex h-5 w-5 items-center justify-center rounded-[5px] border border-[var(--border-strong)] bg-[var(--bg-surface)] text-[var(--text-secondary)] transition-colors hover:enabled:bg-[var(--bg-hover)] hover:enabled:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-35"
                >
                  <ChevronRight size={11} />
                </button>
              </div>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
