"""
report.py — Stage 7
Generates a readable incident PDF from events captured in SQLite.

Reliability checkpoint this file must pass:
  - Report generation doesn't fail on 0 events
  - Report generation doesn't fail on events with missing attribution
    (pid=None, process_name="unknown", attribution_confidence="unknown")
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

import config
from events import Event, EventStore

SEVERITY_COLOR = {
    "critical": colors.HexColor("#B00020"),
    "warning": colors.HexColor("#B36B00"),
    "info": colors.HexColor("#2E7D32"),
    None: colors.grey,
}


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "unknown"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _safe(val, default: str = "unknown") -> str:
    """Never let a missing/None field blow up table rendering."""
    if val is None or val == "":
        return default
    return str(val)


def _summarize(events: list[Event]) -> dict:
    total = len(events)
    by_severity = {"critical": 0, "warning": 0, "info": 0, "unset": 0}
    by_confidence = {"high": 0, "ambiguous": 0, "unknown": 0}
    unique_files = set()
    unique_pids = set()

    for e in events:
        sev = e.severity if e.severity in by_severity else "unset"
        by_severity[sev] += 1
        conf = e.attribution_confidence if e.attribution_confidence in by_confidence else "unknown"
        by_confidence[conf] += 1
        unique_files.add(e.file_path)
        if e.pid is not None:
            unique_pids.add(e.pid)

    span = None
    if total:
        ts_sorted = sorted(e.timestamp for e in events)
        span = (ts_sorted[0], ts_sorted[-1])

    return {
        "total": total,
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "unique_files": len(unique_files),
        "unique_pids": len(unique_pids),
        "span": span,
    }


def generate_report(
    output_path: str,
    store: Optional[EventStore] = None,
    limit: int = 500,
    title: str = "Tripwire Incident Report",
) -> str:
    """Build a PDF at output_path from the most recent `limit` events in the
    store. Always produces a valid PDF, even with zero events or events that
    have no attribution — degraded data is rendered as 'unknown', never a
    crash."""
    store = store or EventStore()
    # recent_events() returns newest-first; report reads best chronologically.
    events = list(reversed(store.recent_events(limit=limit)))

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="MetaSmall", parent=styles["Normal"], fontSize=8, textColor=colors.grey,
    ))
    story = []

    # ── Header ──
    story.append(Paragraph(title, styles["Title"]))
    story.append(Paragraph(
        f"Generated {datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')}",
        styles["MetaSmall"],
    ))
    story.append(Spacer(1, 14))

    summary = _summarize(events)

    # ── Summary section ──
    story.append(Paragraph("Summary", styles["Heading2"]))
    if summary["total"] == 0:
        story.append(Paragraph(
            "No events were captured in this window. This is a valid, empty "
            "report — the pipeline did not fail; there is simply nothing to show.",
            styles["Normal"],
        ))
    else:
        span_txt = "n/a"
        if summary["span"]:
            span_txt = f"{_fmt_ts(summary['span'][0])} \u2192 {_fmt_ts(summary['span'][1])}"
        summary_rows = [
            ["Total events", str(summary["total"])],
            ["Time span", span_txt],
            ["Unique files touched", str(summary["unique_files"])],
            ["Unique PIDs observed", str(summary["unique_pids"])],
            ["Critical / Warning / Info",
             f"{summary['by_severity']['critical']} / "
             f"{summary['by_severity']['warning']} / "
             f"{summary['by_severity']['info']}"],
            ["Attribution — high / ambiguous / unknown",
             f"{summary['by_confidence']['high']} / "
             f"{summary['by_confidence']['ambiguous']} / "
             f"{summary['by_confidence']['unknown']}"],
            ["Dead-lettered (malformed) events", str(store.dead_letter_count())],
        ]
        t = Table(summary_rows, colWidths=[2.6 * inch, 3.4 * inch])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#DDDDDD")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(t)

        if summary["by_confidence"]["unknown"] or summary["by_confidence"]["ambiguous"]:
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                "Note: true 100% reliable process attribution at syscall time requires "
                "OS-level hooking (eBPF on Linux, ETW on Windows), which is out of scope "
                "for this build. Events marked 'ambiguous' or 'unknown' reflect that "
                "known limitation rather than a bug.",
                styles["MetaSmall"],
            ))

    story.append(Spacer(1, 16))

    # ── Event log ──
    story.append(Paragraph("Event Log", styles["Heading2"]))
    if summary["total"] == 0:
        story.append(Paragraph("(no events to display)", styles["Normal"]))
    else:
        header = ["Time", "Type", "File", "Sev", "PID", "Process", "Confidence", "MITRE"]
        rows = [header]
        for e in events:
            rows.append([
                _fmt_ts(e.timestamp),
                _safe(e.event_type),
                _safe(e.file_path),
                _safe(e.severity, "info"),
                _safe(e.pid, "-"),
                _safe(e.process_name),
                _safe(e.attribution_confidence),
                _safe(e.mitre_id, "-"),
            ])

        col_widths = [0.95 * inch, 0.55 * inch, 1.55 * inch, 0.45 * inch,
                      0.45 * inch, 0.85 * inch, 0.75 * inch, 0.55 * inch]
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        base_style = [
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i, e in enumerate(events, start=1):  # +1 for header row
            color = SEVERITY_COLOR.get(e.severity, colors.grey)
            base_style.append(("TEXTCOLOR", (3, i), (3, i), color))
        table.setStyle(TableStyle(base_style))
        story.append(table)

    doc.build(story)
    return output_path


# ─── Self-test: reliability checkpoint ──────────────────────────────────────

def _run_self_test():
    import tempfile, shutil

    tmp_dir = tempfile.mkdtemp()
    db_path = os.path.join(tmp_dir, "test.db")
    store = EventStore(db_path=db_path)

    try:
        print("[1/4] report generation on an EMPTY event store doesn't fail ... ", end="")
        out0 = os.path.join(tmp_dir, "empty.pdf")
        generate_report(out0, store=store)
        assert os.path.exists(out0) and os.path.getsize(out0) > 0
        print(f"OK -> {os.path.getsize(out0)} bytes")

        print("[2/4] report handles events with MISSING attribution (None/unknown) ... ", end="")
        store.insert_event(Event(event_type="read", file_path="decoys/mystery.csv"))
        store.insert_event(Event(
            event_type="delete", file_path="decoys/Passwords_Backup.txt",
            severity="critical", mitre_id=config.MITRE_ID_MASS_ACCESS,
        ))
        out1 = os.path.join(tmp_dir, "sparse.pdf")
        generate_report(out1, store=store)
        assert os.path.exists(out1) and os.path.getsize(out1) > 0
        print(f"OK -> {os.path.getsize(out1)} bytes")

        print("[3/4] report handles a FULLY populated, high-severity incident ... ", end="")
        for i in range(5):
            store.insert_event(Event(
                event_type="modify", file_path=f"decoys/burst_{i}.xlsx",
                pid=4821 + i, process_name="sim_attack.exe",
                attribution_confidence="high" if i % 2 == 0 else "ambiguous",
                parent_pid=4800, parent_name="bash",
                severity="critical", mitre_id=config.MITRE_ID_MASS_ACCESS,
            ))
        out2 = os.path.join(tmp_dir, "full.pdf")
        generate_report(out2, store=store)
        assert os.path.exists(out2) and os.path.getsize(out2) > 0
        print(f"OK -> {os.path.getsize(out2)} bytes")

        print("[4/4] a malformed/dead-lettered event doesn't break the summary counts ... ", end="")
        store.insert_dead_letter('{"broken": true', "json.decoder.JSONDecodeError")
        out3 = os.path.join(tmp_dir, "with_dead_letter.pdf")
        generate_report(out3, store=store)
        assert os.path.exists(out3) and os.path.getsize(out3) > 0
        print(f"OK -> {os.path.getsize(out3)} bytes")

        print("\nAll checks passed.")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    _run_self_test()
