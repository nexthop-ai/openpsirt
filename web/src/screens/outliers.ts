// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// An issue a bulk claim covers that does not look like the rest, as far as
// setting it aside needs it: one row per issue, carrying the decision it is
// listed by and every decision the claim holds about it, one per place.
type Outlier = { decision_id: number; decision_ids?: number[] | null };

// Every place of the issue, not one. Setting part of an issue aside leaves its
// other places in the claim, where agreeing to the claim agrees to them.
export function placesOf(row: Outlier): number[] {
  return row.decision_ids && row.decision_ids.length > 0 ? row.decision_ids : [row.decision_id];
}

// The decisions set aside once one issue is ticked or unticked.
export function toggled(held: Set<number>, row: Outlier, on: boolean): Set<number> {
  const next = new Set(held);
  for (const id of placesOf(row)) {
    if (on) next.add(id);
    else next.delete(id);
  }
  return next;
}

// How many issues are set aside, which is what a claim is counted in. The
// decisions number the places, and one issue can sit at many.
export function issuesIn(rows: readonly Outlier[], held: Set<number>): number {
  return rows.filter((row) => held.has(row.decision_id)).length;
}
