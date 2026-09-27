// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { narrowedBy, queueNarrowing } from "./QueueFilters";

describe("queueNarrowing", () => {
  it("carries every filter the address names", () => {
    expect(
      queueNarrowing(
        new URLSearchParams(
          "proposed_by=alice&older_than=30&severity=high&outcome=wont-fix&release=2026.03",
        ),
      ),
    ).toEqual({
      proposed_by: "alice",
      older_than: 30,
      severity: "high",
      outcome: ["wont-fix"],
      release: "2026.03",
    });
  });
  it("leaves out what the server would refuse", () => {
    expect(
      queueNarrowing(
        new URLSearchParams("older_than=soon&severity=awful&outcome=constructor&release=%20"),
      ),
    ).toEqual({});
  });
  it("leaves out low, which excludes nothing", () => {
    expect(queueNarrowing(new URLSearchParams("severity=low"))).toEqual({});
  });
});

describe("narrowedBy", () => {
  it("counts the filters on", () => {
    expect(narrowedBy(new URLSearchParams("proposed_by=alice&release=main&product=x"))).toBe(2);
  });
});
