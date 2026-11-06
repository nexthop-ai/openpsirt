// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The words the trend panels use, and the cases where they say nothing.
//
// Kept out of the screen so the sentences can be tested as sentences. A figure
// that is arithmetically correct and says something false is worse than a
// blank line: the blank invites a question, and the sentence answers one.

// One step of the trend, as much of it as the readings and the chart use.
export type Step = {
  open?: number;
  new?: number;
  corrected?: number;
  returned?: number;
  restored?: number;
  baseline?: number;
  first_scans?: number;
  by_severity?: Record<string, number>;
};

// The steps of real history a sentence about a trend needs.
//
// Four, because the statement is about a direction, and three points is one
// change plus a confirmation. Below it the panels still draw — the chart shows
// what there is and claims nothing — and only the sentence is held back.
const ENOUGH = 4;

// Whether anything was open or moved in a step.
function moved(p: Step): boolean {
  return (
    (p.open ?? 0) > 0 ||
    (p.new ?? 0) > 0 ||
    (p.corrected ?? 0) > 0 ||
    (p.returned ?? 0) > 0 ||
    (p.restored ?? 0) > 0 ||
    (p.baseline ?? 0) > 0 ||
    (p.first_scans ?? 0) > 0
  );
}

// The index of the first step that describes the estate rather than the tool
// being switched on, or the length where none does.
//
// The trend answers for a fixed window whether or not this deployment existed
// through it, so a week-old deployment gets twelve weekly steps of which
// eleven are zeros. Measured across all twelve, a real week-old deployment
// reads "open up 5,803 across the range" and "Critical went 0 → 389": both
// arithmetically correct, and both describing the first scan landing.
//
// Leading empty steps are dropped and the rest are kept. An empty step in the
// middle is real: nothing opened and nothing closed is something that
// happened. A leading one is only the absence of us.
export function began(points: Step[]): number {
  const at = points.findIndex(moved);
  return at < 0 ? points.length : at;
}

// The steps from where the history begins.
export function settled<T extends Step>(points: T[]): T[] {
  return points.slice(began(points));
}

// Whether what arrived in a step outran what was corrected: new and returned
// alike are work arriving.
export function outran(p: Step): boolean {
  return (p.new ?? 0) + (p.returned ?? 0) > (p.corrected ?? 0);
}

// The direction of the backlog, or too little history to say. The unit is the
// step's name, "days" or "weeks".
export function paceReading(points: Step[], unit = "weeks"): string {
  const range = settled(points);
  if (range.length < ENOUGH) return "Not enough history.";
  const ahead = range.filter(outran).length;
  const first = range[0]?.open ?? 0;
  const last = range[range.length - 1]?.open ?? 0;
  const change = last - first;
  const direction = change > 0 ? "growing" : change < 0 ? "shrinking" : "flat";
  const open =
    change === 0
      ? `open unchanged at ${last.toLocaleString()}`
      : `open ${change > 0 ? "up" : "down"} ${Math.abs(change).toLocaleString()}`;
  return `Backlog ${direction} · ${open} · new and returned exceeded corrected in ${ahead} of ${range.length} ${unit}`;
}

// The critical share's direction, over the same history.
export function mixReading(points: Step[]): string {
  const range = settled(points);
  if (range.length < ENOUGH) return "Not enough history yet.";
  const first = range[0]?.by_severity?.critical ?? 0;
  const last = range[range.length - 1]?.by_severity?.critical ?? 0;
  if (first === last) return `Critical unchanged at ${last.toLocaleString()}`;
  return `Critical ${first.toLocaleString()} → ${last.toLocaleString()}`;
}
