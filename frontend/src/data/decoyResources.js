/**
 * decoyResources.js
 *
 * The backend only watches config.DECOY_DIR ("decoys/"), which is a flat
 * folder — there is no Desktop/Finance/HR/Backup structure on disk (see
 * backend/decoy_gen.py's DECOY_SPECS for the full, real file list). These
 * categories group the actual decoy files by file type instead, so every
 * sidebar filter matches real events coming off the backend rather than
 * department names that don't correspond to anything.
 */

import { Activity, BarChart3, FileText, Settings, Archive } from "lucide-react";

export const DECOY_CATEGORIES = [
  {
    id: "all",
    label: "All resources",
    icon: Activity,
    extensions: null, // matches everything
  },
  {
    id: "spreadsheets",
    label: "Spreadsheets",
    icon: BarChart3,
    extensions: [".xlsx", ".csv"],
  },
  {
    id: "documents",
    label: "Documents",
    icon: FileText,
    extensions: [".docx"],
  },
  {
    id: "config",
    label: "Config & credentials",
    icon: Settings,
    extensions: [".txt"],
  },
  {
    id: "archives",
    label: "Archives",
    icon: Archive,
    extensions: [".pdf"],
  },
];

/** True if a resource path (e.g. "decoys/Salary_Details.xlsx") belongs to this category. */
export function categoryMatches(category, resourcePath) {
  if (!resourcePath) return false;
  if (!category.extensions) return true; // "all"
  const lower = resourcePath.toLowerCase();
  return category.extensions.some((ext) => lower.endsWith(ext));
}

/** Count of events whose resource falls into this category. */
export function countForCategory(category, events) {
  if (!category.extensions) return events.length;
  return events.filter((e) => categoryMatches(category, e.resource)).length;
}
