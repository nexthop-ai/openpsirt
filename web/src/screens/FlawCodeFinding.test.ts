// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { fixedFromCodeFinding, type FlawCodeFinding } from "./FlawCodeFinding";

const CODE_FINDING = {
  occurrence: "abc",
  branch_or_tag: "master",
  variant: "broadcom",
  rule: "clang/unix.Malloc",
  path: "src/a.c",
  state: "recorded-as-flaw",
  suggested: { from: "build", lacking: [], unanalyzed: [] },
  proposed: [{ branch_or_tag: "master", variant: "broadcom", seen: true }],
  recorded_by: "ana",
  recorded_at: "2026-10-01T00:00:00Z",
  fixed_in: [
    {
      branch_or_tag: "master",
      variant: "broadcom",
      not_seen: { run: 9, built: "2026-10-02T00:00:00Z", commit: "0123456789abcdef" },
    },
  ],
} as unknown as FlawCodeFinding;

describe("a flaw recorded from a code finding", () => {
  it("starts a fix on a build its code finding is no longer detected on from the build that did not see it", () => {
    expect(fixedFromCodeFinding(CODE_FINDING, "master", "broadcom")).toContain("0123456789ab");
  });

  it("starts a fix on any other build from nothing", () => {
    expect(fixedFromCodeFinding(CODE_FINDING, "master", "mellanox")).toBe("");
    expect(fixedFromCodeFinding(null, "master", "broadcom")).toBe("");
  });
});
