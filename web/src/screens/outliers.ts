// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// An issue a bulk decision covers that does not look like the rest, as far as
// setting it aside needs it: one row per issue, carrying the record it is
// listed by and every record the decision holds about it, one per occurrence.
type Outlier = { decision_occurrence_id: number; decision_occurrence_ids?: number[] | null };

// Every occurrence of the issue, not one. Setting part of an issue aside leaves its
// other occurrences in the decision, where agreeing to the decision agrees to them.
export function rowsOf(row: Outlier): number[] {
  return row.decision_occurrence_ids && row.decision_occurrence_ids.length > 0
    ? row.decision_occurrence_ids
    : [row.decision_occurrence_id];
}

// The records set aside once one issue is ticked or unticked.
export function toggled(held: Set<number>, row: Outlier, on: boolean): Set<number> {
  const next = new Set(held);
  for (const id of rowsOf(row)) {
    if (on) next.add(id);
    else next.delete(id);
  }
  return next;
}

// How many issues are set aside, which is what a decision is counted in. The
// records number the occurrences, and one issue can sit at many.
export function issuesIn(rows: readonly Outlier[], held: Set<number>): number {
  return rows.filter((row) => held.has(row.decision_occurrence_id)).length;
}
