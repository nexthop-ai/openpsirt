// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Pace, Releases, Ring, paceLabel, paceMarks, tickWords } from "./Charts";
import { mounted } from "../test/mount";

const mount = mounted();

const point = (at: string, open: number, fresh: number, corrected: number, returned = 0) => ({
  at,
  open,
  new: fresh,
  corrected,
  returned,
  by_severity: {},
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
      "Open issues from 1,200 to 12,500 over 3 steps, with new and returned outrunning corrected in 1 of them",
    );
    expect(mount.host().textContent).toContain("12,500 open issues");
    expect(mount.host().textContent).toContain("5.0k");
    expect(mount.host().textContent).toContain("10k");
    const titles = Array.from(mount.host().querySelectorAll("title")).map((t) => t.textContent);
    expect(titles).toContain("01-11: 40 new");
    expect(titles).toContain("01-18: 9 corrected");
  });

  it("starts where scanning began, and marks the first scan rather than drawing it as new", () => {
    // Before the first scan nothing is open, and drawn, the open line's scale
    // would run from zero to the whole inventory.
    mount.render(
      <Pace
        points={[
          point("2026-01-01", 0, 0, 0),
          point("2026-01-02", 0, 0, 0),
          { ...point("2026-01-03", 9800, 0, 0), baseline: 9800, first_scans: 1 },
          point("2026-01-04", 9790, 2, 12),
          point("2026-01-05", 9785, 0, 8, 3),
        ]}
      />,
    );
    const host = mount.host();
    expect(host.querySelector("svg")?.getAttribute("aria-label")).toBe(
      "Open issues from 9,800 to 9,785 over 3 steps, with new and returned outrunning corrected in 0 of them; first scans brought 9,800",
    );
    const titles = Array.from(host.querySelectorAll("title")).map((t) => t.textContent);
    expect(titles).toContain("01-03: first scan: 9,800");
    expect(titles).toContain("01-05: 3 returned");
    expect(titles.some((t) => t?.startsWith("01-01"))).toBe(false);
    // The bars' scale is the flows': twelve corrected fills the band.
    const corrected = Array.from(host.querySelectorAll("rect.bar-res")).map((r) =>
      Number(r.getAttribute("height")),
    );
    expect(Math.max(...corrected)).toBeCloseTo(19);
    // The open line's scale is fitted to what open spans after the first scan.
    expect(host.textContent).not.toContain("0 open");
  });

  it("labels a fitted axis in whole numbers where brief labels would read the same", () => {
    expect(tickWords([8270, 8290])).toEqual([(8270).toLocaleString(), (8290).toLocaleString()]);
    expect(tickWords([0, 5000])).toEqual(["0", "5.0k"]);
  });

  it("moves a mark to the step it stays on once leading steps are dropped", () => {
    const points = [
      point("2026-01-01", 0, 0, 0),
      { ...point("2026-01-02", 5, 0, 0), baseline: 5, first_scans: 1 },
      point("2026-01-03", 5, 0, 0),
    ];
    expect(
      paceMarks(
        points,
        [
          { step: 0, said: "before" },
          { step: 2, said: "a tool changed" },
        ],
        1,
      ),
    ).toEqual([
      { step: 0, said: "01-02: first scan: 5" },
      { step: 1, said: "a tool changed" },
    ]);
    expect(
      paceLabel(
        points.slice(1),
        { line: "", what: "Open", fresh: "new", back: "back", done: "done" },
        "days",
      ),
    ).toBe(
      "Open from 5 to 5 over 2 days, with new and back outrunning done in 0 of them; first scans brought 5",
    );
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
          { branch_or_tag: "202305", open: 4 },
          { branch_or_tag: "202411", branch_or_tag_name: "November", open: 0 },
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
