// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Pace, Releases, Ring } from "./Charts";
import { mounted } from "../test/mount";

const mount = mounted();

const point = (at: string, open: number, opened: number, resolved: number) => ({
  at,
  open,
  opened,
  resolved,
  by_severity: {},
  opened_by_severity: {},
  resolved_by_severity: {},
});

describe("the backlog's pace", () => {
  it("says in words how the backlog moved and how often arrivals outran answers", () => {
    mount.render(
      <Pace
        points={[
          point("2026-01-04", 1200, 0, 0),
          point("2026-01-11", 1500, 40, 10),
          point("2026-01-18", 12500, 3, 9),
        ]}
      />,
    );
    const chart = mount.host().querySelector("svg");
    expect(chart?.getAttribute("aria-label")).toBe(
      "Open findings from 1,200 to 12,500 over 3 steps, with new findings outrunning resolved in 1 of them",
    );
    expect(mount.host().textContent).toContain("12,500 open issues");
    expect(mount.host().textContent).toContain("5.0k");
    expect(mount.host().textContent).toContain("10k");
    const titles = Array.from(mount.host().querySelectorAll("title")).map((t) => t.textContent);
    expect(titles).toContain("01-11: 40 new");
    expect(titles).toContain("01-18: 9 resolved");
  });

  it("draws nothing for no steps, and one step in the middle", () => {
    mount.render(<Pace points={[]} />);
    expect(mount.host().querySelector("svg")).toBeNull();
    mount.render(<Pace points={[point("2026-01-04", 5, 1, 0)]} />);
    expect(mount.host().querySelector("circle")?.getAttribute("cx")).toBe("295");
  });
});

describe("the open issues by severity as a ring", () => {
  it("says nothing is open rather than drawing an empty ring", () => {
    mount.render(<Ring point={point("2026-01-04", 0, 0, 0)} />);
    expect(mount.host().textContent).toBe("Nothing is open.");
  });

  it("keys only the bands something is in", () => {
    mount.render(
      <Ring point={{ ...point("2026-01-04", 3, 0, 0), by_severity: { critical: 2, low: 1 } }} />,
    );
    const keyed = Array.from(mount.host().querySelectorAll(".ringkey li")).map(
      (li) => li.textContent,
    );
    expect(keyed).toHaveLength(2);
    expect(keyed.join(" ")).toContain("critical2");
  });
});

describe("the open issues in each release", () => {
  it("names every release, by its display name where it has one", () => {
    mount.render(
      <Releases
        points={[
          { stream: "202305", open: 4 },
          { stream: "202411", stream_name: "November", open: 0 },
        ]}
      />,
    );
    const names = Array.from(mount.host().querySelectorAll("text")).map((t) => t.textContent);
    expect(names).toContain("202305");
    expect(names).toContain("November");
    // A release with nothing open still draws a sliver, so it is visibly there.
    const bars = Array.from(mount.host().querySelectorAll("rect"));
    expect(bars[1]?.getAttribute("height")).toBe("1");
  });
});
