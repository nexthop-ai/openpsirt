// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "./client";
import { unwrap } from "./queries";

// The review queue at the grain of a decision: one proposer's action, however
// many occurrences it covers. The row carries the decision, what it wrote, how
// far it reaches, and — for a decision over many issues — its outliers.
type QueueRow = Body<"WaitingBody">;
type Outliers = Body<"OutliersBody">;
type FindingRef = Body<"FindingRefBody">;
// The case against agreeing.
type Counter = Body<"CounterBody">;

export type Decision = {
  key: string;
  id: number;
  decisionOccurrenceId: number;
  // The server's own vocabulary, read out of the generated client, so a kind
  // the server adds is a compile error here rather than a decision relabeled.
  kind: QueueRow["decision"]["kind"];
  derivedFrom: number | null;
  title: string;
  product: string;
  outcome: string;
  justification: string;
  // Whom a published statement made from it holds for, where the decision
  // states it. Empty lets the reason decide.
  scope: string;
  deferredUntil: string;
  // What a promise says: the date the work lands by, and for an upgrade the
  // version it moves to.
  committedTo: string;
  upgradeTo: string;
  proposedBy: string;
  proposedAt: string;
  selectedBy: string;
  reasoning: string;
  previouslyApproved: boolean;
  deferredDays: number;
  ageDays: number;
  records: number;
  issues: number;
  occurrences: number;
  builds: string[];
  outliers: Outliers | null;
  // The things a careful reader looks up before agreeing: what was
  // decided about the same issue elsewhere, and how much else at the same
  // occurrence nobody has answered.
  counter: Counter | null;
  // The decision's subject, for the approver's card: the issue, the component
  // and version, how bad, where it sits, and where to open it.
  finding: FindingRef | null;
};

export function decisionOf(row: QueueRow): Decision {
  return {
    key: `decision:${row.decision.id}`,
    id: row.decision.id,
    decisionOccurrenceId: row.decision_occurrence.id ?? 0,
    kind: row.decision.kind,
    derivedFrom: row.decision.derived_from ?? null,
    title: row.occurrence.vulnerability ?? "",
    product: row.occurrence.product_name || row.occurrence.product || "",
    outcome: row.decision_occurrence.outcome ?? "",
    justification: row.decision_occurrence.justification ?? "",
    scope: row.decision_occurrence.scope ?? "",
    deferredUntil: row.decision_occurrence.deferred_until ?? "",
    committedTo: row.decision_occurrence.committed_to ?? "",
    upgradeTo: row.decision_occurrence.upgrade_to ?? "",
    proposedBy:
      row.decision.proposed_by_name ||
      row.decision.proposed_by ||
      row.proposed_by_name ||
      row.proposed_by,
    proposedAt: row.decision.proposed_at,
    selectedBy: row.decision.selected_by ?? row.decision_occurrence.selected_by ?? "",
    reasoning: row.reasoning,
    previouslyApproved: row.previously_approved ?? false,
    deferredDays: row.deferred_days ?? 0,
    ageDays: row.age_days,
    records: row.rows,
    issues: row.issues,
    occurrences: row.occurrences,
    builds: row.builds ?? [],
    outliers: row.outliers ?? null,
    counter: row.counter ?? null,
    finding: row.finding ?? null,
  };
}

// How many decisions wait in the review queue, in one product or across all
// of them. Asked with a limit of zero, which answers the total and reads no
// decision, and under one key per product, so every reader of the same count on
// a screen shares one request. Every reader refreshes it every minute, so two
// counts side by side are equally fresh.
export function useQueueCount(product?: string, options: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: ["queue", "count", product ?? ""],
    refetchInterval: 60_000,
    ...options,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/review-queue", {
          params: { query: { limit: 0, ...(product ? { product } : {}) } },
        }),
      ),
  });
}

// Anything that makes or changes a decision invalidates the same set: the
// queue it may have joined or left, the occurrences it covers, and the findings
// they hang off.
//
// One list, shared by every act on a decision, recording one included. A revision takes back every
// standing approval, and a set missing the decision's own blocks leaves the
// approvals beside the editor showing the old approval as standing — the one
// state the second-person control exists to make visible, reported wrong at
// the moment it changes.
export function useAfterDecision() {
  const queries = useQueryClient();
  return () => {
    void queries.invalidateQueries({ queryKey: ["queue"] });
    void queries.invalidateQueries({ queryKey: ["decision-occurrence"] });
    void queries.invalidateQueries({ queryKey: ["decided"] });
    void queries.invalidateQueries({ queryKey: ["finding"] });
    void queries.invalidateQueries({ queryKey: ["home"] });
    // And the proposer's own list, which is where a decision they split
    // appears as two.
    void queries.invalidateQueries({ queryKey: ["my-decisions"] });
    // The decision's own blocks: what it has said, and who agreed to it. Both
    // change under a revision and neither list held them.
    void queries.invalidateQueries({ queryKey: ["decision"] });
    void queries.invalidateQueries({ queryKey: ["comments"] });
    // A decision about a lead moves where the lead stands, and the queue it is
    // listed in.
    void queries.invalidateQueries({ queryKey: ["leads"] });
    void queries.invalidateQueries({ queryKey: ["lead"] });
    // And the list the work came from. A decision answers findings, so
    // agreeing to one moves what the list says about every occurrence it
    // covers.
    void queries.invalidateQueries({ queryKey: ["findings"] });
    // And what an advisory states about a release, which follows the
    // decisions covering it.
    void queries.invalidateQueries({ queryKey: ["advisory"] });
    void queries.invalidateQueries({ queryKey: ["advisory-document"] });
    void queries.invalidateQueries({ queryKey: ["advisory-releases"] });
  };
}

// Approving a decision agrees to every occurrence it covers, except any set
// aside, which return to the proposer as a decision of their own.
export function useApproveDecision() {
  const done = useAfterDecision();
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
        await api.POST("/v1/decisions/{id}/approval", {
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

// Rejecting a decision sends every occurrence it covers back to the proposer, with
// the reason as a comment.
export function useRejectDecision() {
  const done = useAfterDecision();
  return useMutation({
    mutationFn: async ({ id, because }: { id: number; because: string }) =>
      unwrap(
        await api.POST("/v1/decisions/{id}/send-back", {
          params: { path: { id } },
          body: { because },
        }),
      ),
    onSuccess: done,
  });
}

// Holding part of your own decision back: the proposer's side of setting rows
// aside. The rows move into a decision of their own, with you, carrying the
// argument they were made under — and it is a revision that gives them one of
// their own.
export function useSplitDecision() {
  const done = useAfterDecision();
  return useMutation({
    mutationFn: async ({ id, rows, because }: { id: number; rows: number[]; because: string }) =>
      unwrap(
        await api.POST("/v1/decisions/{id}/split", {
          params: { path: { id } },
          body: { rows, because },
        }),
      ),
    onSuccess: done,
  });
}

// Who agreed to one decision, and its revisions: read under one key each by
// every block that draws them, so an act on the decision refreshes all of them.
export function useDecisionApprovals(id: number) {
  return useQuery({
    queryKey: ["decision", id, "approvals"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/decisions/{id}/approvals", { params: { path: { id } } })),
  });
}

export function useDecisionRevisions(id: number) {
  return useQuery({
    queryKey: ["decision", id, "revisions"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/decisions/{id}/revisions", { params: { path: { id } } })),
  });
}
