// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { fixedFromLead, type FlawLead } from "./FlawLead";

const LEAD = {
  place: "abc",
  stream: "master",
  variant: "broadcom",
  rule: "clang/unix.Malloc",
  path: "src/a.c",
  state: "handed-off",
  suggested: { from: "build", lacking: [], unanalyzed: [] },
  proposed: [{ stream: "master", variant: "broadcom", seen: true }],
  handed_by: "ana",
  handed_at: "2026-10-01T00:00:00Z",
  fixed_in: [
    {
      stream: "master",
      variant: "broadcom",
      not_seen: { run: 9, built: "2026-10-02T00:00:00Z", commit: "0123456789abcdef" },
    },
  ],
} as unknown as FlawLead;

describe("a flaw recorded from a lead", () => {
  it("starts a fix on a build its lead is not reproduced on from the build that did not see it", () => {
    expect(fixedFromLead(LEAD, "master", "broadcom")).toContain("0123456789ab");
  });

  it("starts a fix on any other build from nothing", () => {
    expect(fixedFromLead(LEAD, "master", "mellanox")).toBe("");
    expect(fixedFromLead(null, "master", "broadcom")).toBe("");
  });
});
