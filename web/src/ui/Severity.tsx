import { isBand } from "./severities";

// Severity reads at a glance and never borrows the accent color: "urgent" and
// "clickable" must never look like the same thing.
//
// The rating and the fact are shown separately, because they are separate.
// Severity says how bad the flaw is; being exploited says somebody is using
// it. Replacing "medium" with "exploited" answers one question by destroying
// the other — and the two together are what explain why an exploited medium
// sits above an unexploited high in the list.
export function Severity({ word }: { word?: string }) {
  // One word for one state. A scanner's own "unknown", a producer's invented
  // word and no rating at all rank alike everywhere that orders or filters —
  // below every band, surviving no floor — and only what a reader saw
  // differed: one row said "Unknown" and the row under it said "Unrated"
  // about the same nothing.
  const shown = isBand(word ?? "") ? (word as string) : "unrated";
  const known = isBand(shown);
  return (
    <span className={`sev ${known ? shown : "low"}`}>
      {shown[0]?.toUpperCase()}
      {shown.slice(1)}
    </span>
  );
}

// Known-exploited, said outright rather than left to a color. It is a fact
// about the world rather than a judgment, and it is what decides the order.
export function Exploited({ when }: { when?: boolean }) {
  if (!when) return null;
  return (
    <span
      className="kev"
      title="Somebody is known to be using this. It sorts above everything else, whatever the severity says"
    >
      Exploited
    </span>
  );
}
