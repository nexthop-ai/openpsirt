// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Became, Happened } from "./QueueMine";
import { accept, mounted, screen, settle } from "../test/mount";
import { button, only, change } from "../test/controls";
import type { Body } from "../api/client";

const mount = mounted();

const settled = { isPending: false, isError: false, error: null };

const ROW = {
  happened: "waiting",
  by: "bo",
  decision: { id: 41 },
  occurrence: { vulnerability: "CVE-2026-1", product: "sonic" },
  finding: {
    product: "sonic",
    branch_or_tag: "master",
    variant: "arm",
    vulnerability: "CVE-2026-1",
    component: "zlib",
    version: "1.2",
  },
  issues: 3,
  rows: 7,
  occurrences: 7,
  when: "2026-01-01T00:00:00Z",
  outliers: {
    rows: [
      {
        decision_occurrence_id: 5,
        decision_occurrence_ids: [5, 6],
        vulnerability: "CVE-2026-2",
        why: ["exploited"],
      },
      {
        decision_occurrence_id: 8,
        decision_occurrence_ids: [8],
        vulnerability: "CVE-2026-3",
        why: ["fix available"],
      },
    ],
  },
} as unknown as Body<"BecameBody">;

const text = () => mount.host().textContent ?? "";

describe("the decisions somebody proposed", () => {
  it("holds back every occurrence of an outlier, and only with a reason", async () => {
    const sent = accept(() => ({ data: {} }));
    mount.render(screen(<Became rows={[ROW]} query={settled} />));
    await settle();
    expect(text()).toContain("3 issues · 7 rows");
    const [first] = Array.from(
      mount.host().querySelectorAll<HTMLInputElement>('input[aria-label="Hold back"]'),
    );
    await act(async () => first?.click());
    expect(button(mount.host(), "Hold 1 back").disabled).toBe(true);
    change(mount.host().querySelector("textarea"), "these two are exploited");
    await act(async () => button(mount.host(), "Hold 1 back").click());
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/decisions/{id}/split");
    expect(init.params?.path).toEqual({ id: 41 });
    expect(init.body).toEqual({ rows: [5, 6], because: "these two are exploited" });
    expect(mount.host().querySelector("textarea")).toBeNull();
  });

  it("names a correction by source paths and opens the rule, not the issue it is stored against", async () => {
    const rule = {
      ...ROW,
      decision: { id: 2, kind: "source" },
      issues: 661,
      rows: 10547,
      outliers: undefined,
      source: { package: "linux-perf", source: "linux", paths: ["tools/lib", "tools/perf"] },
    } as unknown as Body<"BecameBody">;
    mount.render(screen(<Became rows={[rule]} query={settled} />));
    await settle();
    expect(text()).toContain("By source paths");
    expect(text()).toContain("linux-perf through linux");
    expect(text()).not.toContain("CVE-2026-1");
    expect(text()).not.toContain("master");
    const links = Array.from(mount.host().querySelectorAll("a")).map((a) => a.getAttribute("href"));
    expect(links).toEqual(["/decisions/2"]);
  });

  it("says one decision where a decision covers one issue", async () => {
    mount.render(
      screen(<Became rows={[{ ...ROW, issues: 1, outliers: undefined }]} query={settled} />),
    );
    await settle();
    expect(text()).toContain("one decision");
  });

  it("says nothing was proposed", async () => {
    mount.render(screen(<Became rows={[]} query={settled} />));
    expect(text()).toContain("You have not proposed anything.");
  });
});

describe("what became of a decision", () => {
  it("names each ending, and shows a word it does not know as it arrived", () => {
    mount.render(<Happened word="undone" by="bo" />);
    expect(text()).toBe("Agreement undone by bo");
    mount.render(<Happened word="something-new" />);
    expect(text()).toBe("something-new");
  });
});
