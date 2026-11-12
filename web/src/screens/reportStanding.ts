// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Disposition, Report, Rulable } from "../api/intake";
import { own } from "../ui/own";

// What a report was judged to be, in the words every screen says it in.
const DISPOSITION_SAID: Record<Disposition, string> = {
  accepted: "Accepted",
  duplicate: "Duplicate",
  "not-reproducible": "Not reproducible",
  "out-of-scope": "Out of scope",
  rejected: "Rejected",
};

// What a ruling may carry, in the order the form offers them: whether it waits
// for somebody else, and whether it needs a reason. Keyed by every disposition
// the server takes in a ruling, so one it adds is a compile error here.
// Rejecting and declaring out of scope wait for somebody else; a duplicate's
// reason is the issue it names.
const RULINGS = {
  duplicate: { second: false, reason: false },
  "not-reproducible": { second: false, reason: true },
  "out-of-scope": { second: true, reason: true },
  rejected: { second: true, reason: true },
} satisfies Record<Rulable, { second: boolean; reason: boolean }>;

export const RULABLE = Object.keys(RULINGS) as Rulable[];

// A word the table does not know is shown as it arrived.
export function dispositionSaid(disposition: string | undefined): string {
  if (!disposition) return "";
  return own<string>(DISPOSITION_SAID, disposition) ?? disposition;
}

// Whether a ruling of this disposition waits for somebody else.
export function needsSecond(disposition: Rulable): boolean {
  return RULINGS[disposition].second;
}

// Whether a ruling of this disposition needs a reason.
export function needsReason(disposition: Rulable): boolean {
  return RULINGS[disposition].reason;
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
