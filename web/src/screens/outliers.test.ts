// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { issuesIn, placesOf, toggled } from "./outliers";

const kernel = { decision_id: 10, decision_ids: [10, 11, 12] };
const curl = { decision_id: 20, decision_ids: [20] };
const older = { decision_id: 30 };

describe("setting an issue aside from a bulk claim", () => {
  it("takes every place of the issue with it", () => {
    expect([...toggled(new Set(), kernel, true)]).toEqual([10, 11, 12]);
  });

  it("puts every place back when it is unticked", () => {
    expect([...toggled(new Set([10, 11, 12, 20]), kernel, false)]).toEqual([20]);
  });

  it("falls back to the row's own decision where the places are not listed", () => {
    expect(placesOf(older)).toEqual([30]);
    expect(placesOf({ decision_id: 40, decision_ids: null })).toEqual([40]);
  });

  it("counts issues set aside rather than the places they sit at", () => {
    const held = toggled(toggled(new Set(), kernel, true), curl, true);
    expect(held.size).toBe(4);
    expect(issuesIn([kernel, curl, older], held)).toBe(2);
  });
});
