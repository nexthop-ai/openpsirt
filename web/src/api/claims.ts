// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// The review queue at the grain of a claim: one proposer's action, however
// many decisions it wrote. The row carries the claim, what it wrote, how far
// it reaches, and — for a claim over many issues — its outliers.
export type QueueRow = Body<"WaitingBody">;
export type Outliers = Body<"OutliersBody">;
export type FindingRef = Body<"FindingRefBody">;
// The case against agreeing.
export type Counter = Body<"CounterBody">;

export type Claim = {
  key: string;
  id: number;
  decisionId: number;
  // The server's own vocabulary, read out of the generated client. Restated
  // here and narrowed by hand, the check that did the narrowing could not
  // fail — its three comparisons exhausted every value but one — so a fifth
  // kind would have been silently relabeled as a finding rather than caught.
  kind: QueueRow["claim"]["kind"];
  derivedFrom: number | null;
  title: string;
  product: string;
  outcome: string;
  justification: string;
  deferredUntil: string;
  proposedBy: string;
  proposedAt: string;
  selectedBy: string;
  reasoning: string;
  previouslyApproved: boolean;
  deferredDays: number;
  ageDays: number;
  records: number;
  issues: number;
  places: number;
  builds: string[];
  outliers: Outliers | null;
  // The things a careful reader looks up before agreeing: what was
  // decided about the same issue elsewhere, and how much else at the same
  // place nobody has answered.
  counter: Counter | null;
  // The claim's subject, for the approver's card: the issue, the component
  // and version, how bad, where it sits, and where to open it.
  finding: FindingRef | null;
};

export function claimOf(row: QueueRow): Claim {
  return {
    key: `claim:${row.claim.id}`,
    id: row.claim.id,
    decisionId: row.decision.id ?? 0,
    kind: row.claim.kind,
    derivedFrom: row.claim.derived_from ?? null,
    title: row.place.vulnerability ?? "",
    product: row.place.product ?? "",
    outcome: row.decision.outcome ?? "",
    justification: row.decision.justification ?? "",
    deferredUntil: row.decision.deferred_until ?? "",
    proposedBy:
      row.claim.proposed_by_name ||
      row.claim.proposed_by ||
      row.proposed_by_name ||
      row.proposed_by,
    proposedAt: row.claim.proposed_at,
    selectedBy: row.claim.selected_by ?? row.decision.selected_by ?? "",
    reasoning: row.reasoning,
    previouslyApproved: row.previously_approved ?? false,
    deferredDays: row.deferred_days ?? 0,
    ageDays: row.age_days,
    records: row.decisions,
    issues: row.issues,
    places: row.places,
    builds: row.builds ?? [],
    outliers: row.outliers ?? null,
    counter: row.counter ?? null,
    finding: row.finding ?? null,
  };
}

// Anything that changes a claim invalidates the same set: the queue it may
// have left, the decisions it wrote, and the findings they hang off.
//
// One list, because there were two. A second copy listed four of these
// keys and was used by revising and withdrawing, so a revision — which takes
// back every standing approval — left the revision history and the approvals
// beside the editor showing the old approval as standing. Somebody reading
// that screen concluded the approval had survived the edit, which is the one
// state the second-person control exists to make visible, reported wrong at
// the moment it changes.
export function useAfterClaim() {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: ["queue"] });
    void queries.invalidateQueries({ queryKey: ["decision"] });
    void queries.invalidateQueries({ queryKey: ["decided"] });
    void queries.invalidateQueries({ queryKey: ["finding"] });
    void queries.invalidateQueries({ queryKey: ["home"] });
    // And the proposer's own list, which is where a claim they split appears
    // as two.
    void queries.invalidateQueries({ queryKey: ["my-claims"] });
    // The claim's own blocks: what it has said, and who agreed to it. Both
    // change under a revision and neither list held them.
    void queries.invalidateQueries({ queryKey: ["claim"] });
    void queries.invalidateQueries({ queryKey: ["comments"] });
    // And the list the work came from. A claim answers findings, so agreeing
    // to one moves what the list says about every place it covers — nine
    // other screens invalidate this key after a write and this one did not,
    // which is the shape of a list that silently shows the old answer.
    void queries.invalidateQueries({ queryKey: ["findings"] });
  };
}

// Approving a claim agrees to every decision it wrote, except any set aside ,
// which return to the proposer as a claim of their own.
export function useApproveClaim() {
  const done = useAfterClaim();
  return useMutation({
    mutationFn: async ({
      id,
      batch,
      except,
      because,
    }: {
      id: number;
      batch?: string;
      except?: number[];
      because?: string;
    }) =>
      unwrap(
        await api.POST("/v1/claims/{id}/approval", {
          params: { path: { id } },
          body: {
            ...(batch ? { batch } : {}),
            ...(except && except.length > 0 ? { except, because } : {}),
          },
        }),
      ),
    onSuccess: done,
  });
}

// Rejecting a claim sends every decision it wrote back to the proposer, with
// the reason as a comment.
export function useRejectClaim() {
  const done = useAfterClaim();
  return useMutation({
    mutationFn: async ({ id, because }: { id: number; because: string }) =>
      unwrap(
        await api.POST("/v1/claims/{id}/send-back", {
          params: { path: { id } },
          body: { because },
        }),
      ),
    onSuccess: done,
  });
}

// Holding part of your own claim back: the proposer's side of setting rows
// aside. The rows move into a claim of their own, with you, carrying the
// argument they were made under — and it is a revision that gives them one of
// their own.
export function useSplitClaim() {
  const done = useAfterClaim();
  return useMutation({
    mutationFn: async ({ id, rows, because }: { id: number; rows: number[]; because: string }) =>
      unwrap(
        await api.POST("/v1/claims/{id}/split", {
          params: { path: { id } },
          body: { rows, because },
        }),
      ),
    onSuccess: done,
  });
}
