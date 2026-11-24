// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AddedDone, Burn, type BurnPoint } from "./Burn";
import { mounted } from "../test/mount";

const mount = mounted();

const point = (at: string, left: number): BurnPoint => ({
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
});

describe("the burndown chart, read aloud", () => {
  it("says nothing is left when nothing is, whatever the projection says", () => {
    mount.render(
      <Burn
        points={[point("2026-10-01", 4), point("2026-10-02", 0)]}
        start={4}
        since="2026-10-01"
        ahead={{
          days: 14,
          done: 4,
          added: 0,
          per_day: 2,
          converging: true,
          zero_on: "2026-10-02",
        }}
      />,
    );
    const said = mount.host().querySelector("svg")?.getAttribute("aria-label") ?? "";
    expect(said).toContain("nothing is left");
    expect(said).not.toContain("at this pace");
  });
});

describe("the two burndown panels", () => {
  it("put today at one place on both, where the dotted line widens the left one", () => {
    const points = [point("2026-10-01", 10), point("2026-10-05", 8)];
    const ahead = {
      days: 14,
      done: 2,
      added: 0,
      per_day: 0.5,
      converging: true,
      zero_on: "2026-10-21",
    };
    mount.render(
      <>
        <Burn points={points} start={10} since="2026-10-01" ahead={ahead} />
        <AddedDone points={points} since="2026-10-01" ahead={ahead} />
      </>,
    );
    const [left, totals] = Array.from(mount.host().querySelectorAll("svg"));
    const today = left?.querySelector("circle.tip")?.getAttribute("cx");
    const added = totals?.querySelector("polyline.added-line")?.getAttribute("points") ?? "";
    const lastX = added.trim().split(" ").at(-1)?.split(",")[0];
    expect(today).toBeTruthy();
    expect(Number(lastX)).toBeCloseTo(Number(today));
    // The dotted line runs past today, so today is not the right edge.
    expect(Number(today)).toBeLessThan(560 - 10 - 1);
  });
});
