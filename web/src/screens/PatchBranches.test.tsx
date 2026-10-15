// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { PatchBranches } from "./PatchBranches";
import { mounted, screen, serve, settle } from "../test/mount";
import { press, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const repo = (url: string, of: Record<string, unknown>) => ({
  url,
  host: new URL(url).host,
  commits: 10,
  looked: 4,
  found: 3,
  ...of,
});

async function drawn(repositories: unknown[], total = repositories.length) {
  const spy = serve((path, init) => {
    if (path !== "/v1/patch-branches") return undefined;
    const offset = (init as Init).params?.query?.offset ?? 0;
    return {
      data: {
        on: true,
        looked: 4,
        commits: 10,
        links: 12,
        held_bytes: 0,
        total,
        repositories:
          offset === 0 ? repositories : [repo("https://git.example/later", { state: "done" })],
      },
    };
  });
  mount.render(screen(<PatchBranches />));
  await settle();
  return () =>
    (spy.mock.calls as unknown as [string, Init][]).map(([, init]) => init.params?.query ?? {});
}

const headings = () => Array.from(mount.host().querySelectorAll("h4")).map((h) => h.textContent);
const text = () => mount.host().textContent ?? "";

describe("how far the patch branch lookups have got", () => {
  it("puts a repository with a place in the plan under Next, whatever it last ended as", async () => {
    await drawn([
      repo("https://git.example/now", {
        state: "working",
        step: "looking-up",
        visit_looked: 2,
        due: 3,
      }),
      repo("https://git.example/again", { state: "failed", position: 1, reason: "x" }),
      repo("https://git.example/stale", { state: "done", position: 2, worst: "critical" }),
      repo("https://git.example/broken", {
        state: "failed",
        reason: `${"a".repeat(130)}\nsecond line`,
      }),
      repo("https://git.example/finished", { state: "done", reached_at: "2026-01-01T00:00:00Z" }),
      repo("https://10.0.0.1/inside", { state: "excluded" }),
    ]);
    expect(headings()).toEqual(["Now", "Next", "Failed"]);
    expect(text()).toContain("Looking up 2 of 5 commits");
    expect(text()).toContain(`${"a".repeat(119)}…`);
    expect(text()).not.toContain("second line");
    expect(text()).toContain("Excluded: 10.0.0.1");
    expect(text()).toContain("Done · 1");
    const failedRows = Array.from(mount.host().querySelectorAll("tr")).filter((tr) =>
      tr.textContent?.includes("https://git.example/again"),
    );
    expect(failedRows).toHaveLength(1);
    expect(failedRows[0]?.closest("table")?.textContent).toContain("Worst");
  });

  it("reads the next page when more is asked for", async () => {
    const asked = await drawn([repo("https://git.example/one", { state: "done" })], 201);
    await press(mount.host(), "Show more · 1 of 201");
    await settle();
    expect(asked().at(-1)).toEqual({ limit: 200, offset: 200 });
    expect(text()).toContain("Done · 2");
  });

  it("says no link names a commit", async () => {
    await drawn([]);
    expect(text()).toContain("No patch link names a commit.");
  });
});
