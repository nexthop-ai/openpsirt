// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { CodeFindingTrend } from "../api/codeFindings";
import { markerSaid, partsOf } from "./codeTrend";

describe("the tiers a trend is split by", () => {
  it("draws a tier the trend counts and has no name for, after the named ones", () => {
    const trend = {
      points: [
        {
          at: "2026-11-01",
          by_tier: { "memory-safety": 1, other: 2, crypto: 3 },
          by_method: {},
          by_series: {},
        },
      ],
    } as unknown as CodeFindingTrend;
    expect(partsOf(trend, "tier")).toEqual([
      "memory-safety",
      "input",
      "resource",
      "other",
      "crypto",
    ]);
  });
});

describe("a marker saying a run is not comparable", () => {
  it("says why in words, and that it was for another reason where none is given", () => {
    const marker = {
      at: "2026-11-01",
      product: "sonic",
      series: "semgrep/default",
      change: "not-comparable" as const,
      builds: 1,
    };
    expect(markerSaid({ ...marker, reason: "incomplete" })).toBe(
      "semgrep/default: not comparable, didn't finish",
    );
    expect(markerSaid(marker)).toBe("semgrep/default: not comparable, for another reason");
    expect(markerSaid({ ...marker, reason: "added-later" as never })).toBe(
      "semgrep/default: not comparable, for another reason",
    );
  });
});
