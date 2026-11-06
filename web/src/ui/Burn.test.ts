// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { type BurnPoint, type Projection, paceWords, projectionEnd, running } from "./Burn";

const point = (at: string, left: number, of: Partial<BurnPoint> = {}): BurnPoint => ({
  at,
  left,
  left_by_severity: {},
  new: 0,
  returned: 0,
  fixed: 0,
  dismissed: 0,
  restored: 0,
  baseline: 0,
  first_scans: 0,
  ...of,
});

const pace = (of: Partial<Projection>): Projection => ({
  days: 14,
  done: 0,
  added: 0,
  per_day: 0,
  converging: false,
  ...of,
});

const at = (day: string) => Date.parse(`${day}T00:00:00Z`);

describe("the projection's words", () => {
  it("names the day zero is reached where done outruns added", () => {
    expect(paceWords(pace({ converging: true, per_day: 2, zero_on: "2026-12-01" }), 40)).toBe(
      "zero by 2026-12-01 at this pace",
    );
  });

  it("says it takes more than ten years where the server names no day", () => {
    expect(paceWords(pace({ converging: true, per_day: 0.01 }), 40)).toBe(
      "more than ten years to zero at this pace",
    );
  });

  it("says the backlog grows by about the net a day where added outruns done", () => {
    expect(paceWords(pace({ per_day: -2.34 }), 40)).toBe(
      "not converging: backlog growing about 2.3 a day",
    );
  });

  it("says added keeps pace where the net is zero", () => {
    expect(paceWords(pace({ per_day: 0 }), 40)).toBe("not converging: added keeps pace with done");
  });
});

describe("the dotted line", () => {
  const points = [point("2026-11-01", 20), point("2026-11-05", 10)];

  it("ends at zero on the day it reaches it, inside the chart", () => {
    const end = projectionEnd(
      points,
      pace({ converging: true, per_day: 2, zero_on: "2026-11-10" }),
      at("2026-11-09") + 86_400_000 * 4,
    );
    expect(end).toEqual({ at: at("2026-11-10"), left: 0 });
  });

  it("ends at the right edge at what it would show there, where zero is past it", () => {
    const end = projectionEnd(
      points,
      pace({ converging: true, per_day: 1, zero_on: "2026-11-15" }),
      at("2026-11-09"),
    );
    expect(end).toEqual({ at: at("2026-11-09"), left: 6 });
  });

  it("is not drawn where the backlog does not converge", () => {
    expect(projectionEnd(points, pace({ per_day: -1 }), at("2026-11-09"))).toBeNull();
  });
});

describe("the running totals", () => {
  it("count new and returned as added, fixed and dismissed as done, from zero", () => {
    expect(
      running([
        point("2026-11-01", 5, { new: 2, returned: 1, fixed: 1 }),
        point("2026-11-02", 4, { new: 1, dismissed: 2, restored: 9, baseline: 9 }),
      ]),
    ).toEqual([
      { at: "2026-11-01", added: 3, done: 1 },
      { at: "2026-11-02", added: 4, done: 3 },
    ]);
  });
});
