import { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { MITRE_LABELS } from "../../data/mockEvents";
import { MITRE_DETAILS } from "../../data/previewContent";

export function MitreCard({ mitreId, event }) {
  const [open, setOpen] = useState(false);
  const id = mitreId || "T1486";
  const detail = MITRE_DETAILS[id];

  return (
    <div className="mitre-card">
      <button className="mitre-card-summary" onClick={() => setOpen((o) => !o)}>
        <div>
          <strong>{id}</strong>
          <span>{MITRE_LABELS[id] || detail?.name || "Data Encrypted for Impact"}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span className="mitre-badge">{detail?.tactic || "Technique"}</span>
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </div>
      </button>

      {open && (
        <div className="mitre-detail">
          <p>{detail?.description || "No technique detail available."}</p>

          <div className="mitre-detail-row">
            <span>Matched touch pattern</span>
            <strong>{event?.touchCount ? `${event.touchCount} touches` : "—"}</strong>
          </div>
          <div className="mitre-detail-row">
            <span>Triggering decoy</span>
            <strong>{event?.filename || "—"}</strong>
          </div>
          <div className="mitre-detail-row">
            <span>Placement</span>
            <strong>{event?.placementLabel || "—"}</strong>
          </div>
        </div>
      )}
    </div>
  );
}
