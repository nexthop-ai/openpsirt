import type { Disposition, Report, Rulable } from "../api/intake";

// What a report was judged to be, in the words every screen says it in.
export const DISPOSITION_SAID: Record<Disposition, string> = {
  accepted: "Accepted",
  duplicate: "Duplicate",
  "not-reproducible": "Not reproducible",
  "out-of-scope": "Out of scope",
  rejected: "Rejected",
};

// The four a ruling carries, in the order the form offers them.
export const RULABLE: readonly Rulable[] = [
  "duplicate",
  "not-reproducible",
  "out-of-scope",
  "rejected",
];

// A word the table does not know is shown as it arrived.
export function dispositionSaid(disposition: string | undefined): string {
  if (!disposition) return "";
  return DISPOSITION_SAID[disposition as Disposition] ?? disposition;
}

// Rejecting and declaring out of scope wait for somebody else.
export function needsSecond(disposition: Rulable): boolean {
  return disposition === "out-of-scope" || disposition === "rejected";
}

// A duplicate's reason is the issue it names.
export function needsReason(disposition: Rulable): boolean {
  return disposition !== "duplicate";
}

// Where a report stands, as the one word its row shows.
export function standing(report: Report): { said: string; tone: string } {
  if (report.disposition) {
    return { said: dispositionSaid(report.disposition), tone: "agreed" };
  }
  if (report.waiting) {
    return { said: `${dispositionSaid(report.waiting)}, waiting`, tone: "waiting" };
  }
  return { said: "Open", tone: "open" };
}

// Whether a report may be put under a ruling: nothing has answered it and no
// ruling holds it.
export function rulable(report: Report): boolean {
  return !report.disposition && !report.ruling;
}

// Whether a ruling as typed is one the server would take.
export function ready(ruling: {
  disposition: Rulable | "";
  reasoning: string;
  duplicateOf: string;
}): boolean {
  if (!ruling.disposition) return false;
  if (ruling.disposition === "duplicate" && ruling.duplicateOf.trim() === "") return false;
  return !needsReason(ruling.disposition) || ruling.reasoning.trim() !== "";
}
