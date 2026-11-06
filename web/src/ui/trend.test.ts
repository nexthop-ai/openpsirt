// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { mixReading, paceReading, settled } from "./trend";

// A week of real data, as the trend endpoint answers it: a fixed window of
// twelve weekly steps, of which eleven predate this deployment entirely.
const justSwitchedOn = [
  ...Array.from({ length: 11 }, () => ({ open: 0, new: 0, corrected: 0, by_severity: {} })),
  {
    open: 5803,
    new: 0,
    corrected: 0,
    baseline: 5803,
    first_scans: 1,
    by_severity: { critical: 389 },
  },
];

describe("what the trend panels say", () => {
  it("says nothing about a deployment that was just switched on", () => {
    // measured. It read "Backlog growing: new exceeded resolved in 1 of 12
    // weeks; open up 5,803 across the range" and "Critical went 0 → 389" —
    // both arithmetically correct, and both describing the first scan landing
    // rather than anything about the estate.
    expect(paceReading(justSwitchedOn)).toBe("Not enough history.");
    expect(mixReading(justSwitchedOn)).toBe("Not enough history yet.");
  });

  it("says nothing at all where nothing has been scanned", () => {
    const nothing = Array.from({ length: 12 }, () => ({ open: 0, new: 0, corrected: 0 }));
    expect(settled(nothing)).toEqual([]);
    expect(paceReading(nothing)).toContain("Not enough history");
  });

  it("measures from where the history begins, not from the window", () => {
    // Eight empty weeks and four real ones. The reading is about the four:
    // the range it names, and the direction it claims, both come from what
    // this deployment actually saw.
    const points = [
      ...Array.from({ length: 8 }, () => ({ open: 0, new: 0, corrected: 0, by_severity: {} })),
      { open: 100, new: 100, corrected: 0, by_severity: { critical: 10 } },
      { open: 90, new: 2, corrected: 12, by_severity: { critical: 9 } },
      { open: 80, new: 1, corrected: 11, by_severity: { critical: 8 } },
      { open: 70, new: 0, corrected: 10, by_severity: { critical: 6 } },
    ];
    const said = paceReading(points);
    expect(said).toContain("Backlog shrinking");
    expect(said).toContain("of 4 weeks");
    expect(said).toContain("down 30");
    expect(mixReading(points)).toBe("Critical 10 → 6");
  });

  it("keeps an empty week that falls inside the history", () => {
    // Nothing opened and nothing closed is something that happened. Only a
    // leading empty step is the absence of us rather than a quiet week.
    //
    // The interior empty step is what makes this more than a test of the
    // leading one: with every non-leading step non-empty, dropping every
    // empty step rather than only the run at the front passes too, and a
    // quiet week then disappears from the history it belongs to.
    const points = [
      { open: 0, new: 0, corrected: 0 },
      { open: 50, new: 50, corrected: 0 },
      { open: 50, new: 0, corrected: 0 },
      { open: 0, new: 0, corrected: 0 },
      { open: 50, new: 0, corrected: 0 },
      { open: 45, new: 0, corrected: 5 },
    ];
    expect(settled(points)).toHaveLength(5);
    expect(paceReading(points)).toContain("of 5 weeks");
  });

  it("says a backlog that ends where it began is unchanged", () => {
    const points = [
      { open: 40, new: 40, corrected: 0, by_severity: { critical: 4 } },
      { open: 45, new: 5, corrected: 0, by_severity: { critical: 4 } },
      { open: 42, new: 0, corrected: 3, by_severity: { critical: 4 } },
      { open: 40, new: 0, corrected: 2, by_severity: { critical: 4 } },
    ];
    const said = paceReading(points);
    expect(said).toContain("Backlog flat");
    expect(said).toContain("open unchanged at 40");
    expect(said).not.toContain("up 0");
  });
});
