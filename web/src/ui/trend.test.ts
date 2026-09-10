import { describe, expect, it } from "vitest";
import { mixReading, paceReading, settled } from "./trend";

// A week of real data, as the trend endpoint answers it: a fixed window of
// twelve weekly steps, of which eleven predate this deployment entirely.
const justSwitchedOn = [
  ...Array.from({ length: 11 }, () => ({ open: 0, opened: 0, resolved: 0, by_severity: {} })),
  { open: 5803, opened: 5803, resolved: 0, by_severity: { critical: 389 } },
];

describe("what the trend panels say", () => {
  it("says nothing about a deployment that was just switched on", () => {
    // measured. It read "Backlog growing: new exceeded resolved in 1 of 12
    // weeks; open up 5,803 across the range" and "Critical went 0 → 389" —
    // both arithmetically correct, and both describing the first scan landing
    // rather than anything about the estate.
    expect(paceReading(justSwitchedOn)).toBe(
      "Not enough history yet to say which way this is going.",
    );
    expect(mixReading(justSwitchedOn)).toBe("Not enough history yet.");
  });

  it("says nothing at all where nothing has been scanned", () => {
    const nothing = Array.from({ length: 12 }, () => ({ open: 0, opened: 0, resolved: 0 }));
    expect(settled(nothing)).toEqual([]);
    expect(paceReading(nothing)).toContain("Not enough history");
  });

  it("measures from where the history begins, not from the window", () => {
    // Eight empty weeks and four real ones. The reading is about the four:
    // the range it names, and the direction it claims, both come from what
    // this deployment actually saw.
    const points = [
      ...Array.from({ length: 8 }, () => ({ open: 0, opened: 0, resolved: 0, by_severity: {} })),
      { open: 100, opened: 100, resolved: 0, by_severity: { critical: 10 } },
      { open: 90, opened: 2, resolved: 12, by_severity: { critical: 9 } },
      { open: 80, opened: 1, resolved: 11, by_severity: { critical: 8 } },
      { open: 70, opened: 0, resolved: 10, by_severity: { critical: 6 } },
    ];
    const said = paceReading(points);
    expect(said).toContain("Backlog shrinking");
    expect(said).toContain("of 4 weeks");
    expect(said).toContain("down 30");
    expect(mixReading(points)).toBe("Critical went 10 → 6 across the range.");
  });

  it("keeps an empty week that falls inside the history", () => {
    // Nothing opened and nothing closed is something that happened. Only a
    // leading empty step is the absence of us rather than a quiet week.
    const points = [
      { open: 0, opened: 0, resolved: 0 },
      { open: 50, opened: 50, resolved: 0 },
      { open: 50, opened: 0, resolved: 0 },
      { open: 50, opened: 0, resolved: 0 },
      { open: 45, opened: 0, resolved: 5 },
    ];
    expect(settled(points)).toHaveLength(4);
    expect(paceReading(points)).toContain("of 4 weeks");
  });
});
