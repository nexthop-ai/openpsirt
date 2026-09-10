// What the trend panels say in words, and when they say nothing.
//
// Kept out of the screen so the sentences can be tested as sentences. A figure
// that is arithmetically correct and says something false is worse than a
// blank line: the blank invites a question, and the sentence answers one.

// One step of the trend, as much of it as the readings use.
export type Step = {
  open?: number;
  opened?: number;
  resolved?: number;
  by_severity?: Record<string, number>;
};

// How many steps of real history a sentence about a trend needs.
//
// Four, because the statement is about a direction, and three points is one
// change plus a confirmation. Below it the panels still draw — the chart shows
// what there is and claims nothing — and only the sentence is held back.
const ENOUGH = 4;

// The steps that describe the estate rather than the tool being switched on.
//
// The trend answers for a fixed window whether or not this deployment existed
// through it, so a week-old deployment gets twelve weekly steps of which
// eleven are zeros. Measured across all twelve, the copy read "Backlog
// growing: open up 5,803 across the range" and "Critical went 0 → 389" — both
// arithmetically correct, and both describing the first scan landing rather
// than anything about the estate.
//
// Leading empty steps are dropped and the rest are kept. An empty week in the
// middle is real: nothing opened and nothing closed is something that
// happened. A leading one is only the absence of us.
export function settled<T extends Step>(points: T[]): T[] {
  const began = points.findIndex(
    (p) => (p.open ?? 0) > 0 || (p.opened ?? 0) > 0 || (p.resolved ?? 0) > 0,
  );
  return began < 0 ? [] : points.slice(began);
}

// Which way the backlog is going, or that it is too early to say.
export function paceReading(points: Step[]): string {
  const range = settled(points);
  if (range.length < ENOUGH) return "Not enough history yet to say which way this is going.";
  const outran = range.filter((p) => (p.opened ?? 0) > (p.resolved ?? 0)).length;
  const first = range[0]?.open ?? 0;
  const last = range[range.length - 1]?.open ?? 0;
  const moved = last - first;
  const direction = moved > 0 ? "growing" : moved < 0 ? "shrinking" : "flat";
  return `Backlog ${direction}: new exceeded resolved in ${outran} of ${range.length} weeks; open ${
    moved >= 0 ? "up" : "down"
  } ${Math.abs(moved).toLocaleString()} across the range.`;
}

// What the critical share did, over the same history.
export function mixReading(points: Step[]): string {
  const range = settled(points);
  if (range.length < ENOUGH) return "Not enough history yet.";
  const first = range[0]?.by_severity?.critical ?? 0;
  const last = range[range.length - 1]?.by_severity?.critical ?? 0;
  if (first === last) return `Critical unchanged at ${last.toLocaleString()} across the range.`;
  return `Critical went ${first.toLocaleString()} → ${last.toLocaleString()} across the range.`;
}
