// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { issuesIn, rowsOf, toggled } from "./outliers";

const kernel = { decision_occurrence_id: 10, decision_occurrence_ids: [10, 11, 12] };
const curl = { decision_occurrence_id: 20, decision_occurrence_ids: [20] };
const older = { decision_occurrence_id: 30 };

describe("setting an issue aside from a bulk decision", () => {
  it("takes every occurrence of the issue with it", () => {
    expect([...toggled(new Set(), kernel, true)]).toEqual([10, 11, 12]);
  });

  it("puts every occurrence back when it is unticked", () => {
    expect([...toggled(new Set([10, 11, 12, 20]), kernel, false)]).toEqual([20]);
  });

  it("falls back to the row's own decision where the occurrences are not listed", () => {
    expect(rowsOf(older)).toEqual([30]);
    expect(rowsOf({ decision_occurrence_id: 40, decision_occurrence_ids: null })).toEqual([40]);
  });

  it("counts issues set aside rather than the occurrences they sit at", () => {
    const held = toggled(toggled(new Set(), kernel, true), curl, true);
    expect(held.size).toBe(4);
    expect(issuesIn([kernel, curl, older], held)).toBe(2);
  });
});
