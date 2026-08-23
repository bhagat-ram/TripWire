/**
 * previewContent.js
 *
 * The dashboard never reads real file bytes over the wire — the backend's
 * WebSocket contract carries metadata about a touch, not file contents.
 * These helpers generate a plausible, clearly-labeled preview so the
 * InvestigationDrawer can show "what the decoy looks like" without
 * pretending to stream real bytes.
 */

const EXT_PREVIEW = {
  csv: (name) =>
    `id,name,department,value,notes\n1,Person_4821,Finance,168450.00,confidential\n2,Person_2290,Legal,94200.00,confidential\n3,Person_9142,Engineering,142000.00,confidential\n… ${name} continues`,
  xlsx: (name) =>
    `[Sheet1] A1:E1 id | name | department | value | notes\nA2:E2  1 | Person_4821 | Finance | 168450.00 | confidential\n… ${name} continues`,
  docx: (name) =>
    `CONFIDENTIAL — ${name}\n========================================\nentry_01: ref-482113\nentry_02: ref-229087\nentry_03: ref-914452\n…`,
  pdf: () => `%PDF-1.4\n%tripwire-decoy\n<binary payload — 2,000–8,000 bytes of decoy content>`,
  txt: (name) =>
    `CONFIDENTIAL — ${name}\n========================================\nentry_01: ref-482113\nentry_02: ref-229087\n…`,
  json: (name) => `{\n  "type": "service_account",\n  "note": "decoy credential — ${name}"\n}`,
};

/** Returns a short, labeled content preview string for a decoy filename. */
export function previewForFilename(filename) {
  if (!filename) return "No preview available.";
  const ext = filename.split(".").pop()?.toLowerCase();
  const gen = EXT_PREVIEW[ext];
  return gen ? gen(filename) : `<decoy content for ${filename}>`;
}

export const MITRE_DETAILS = {
  T1486: {
    name: "Data Encrypted for Impact",
    tactic: "Impact",
    description:
      "Adversaries encrypt or otherwise render data inaccessible, typically as the final stage of a ransomware attack. Rapid, sequential touches across multiple decoy files in a short window is the pattern this technique maps to.",
  },
  T1083: {
    name: "File and Directory Discovery",
    tactic: "Discovery",
    description:
      "Adversaries enumerate files and directories to find valuable data before acting on it. A slower, broader sweep across decoy locations without modification maps to this technique.",
  },
};
