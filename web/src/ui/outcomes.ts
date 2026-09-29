// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import type { Body } from "../api/client";
import { useWho } from "../app/session";

// Every outcome the server records, read from the published API document so a
// word the server adds is a compile error wherever a screen names it.
export type Outcome = NonNullable<Body<"DisposedBody">["outcome"]>;

// What one outcome claims, as the server publishes it beside the caller.
export type Claims = Body<"OutcomeBody">;

// The outcomes sorted by what they claim, in the terms the server counts,
// filters and refuses by. Built from what the server publishes rather than
// kept here, so an outcome it moves to another class moves here too.
//
// | Field | Means |
// |---|---|
// | known | the server's answer has arrived; until it has, nothing is in any class |
// | dismissing | the server calls it a dismissal: it hides risk and stores no date |
// | hidesRisk | recording it takes the issue out of the working queue |
// | dated | it stores a date: a review date, or when promised work lands |
// | needsJustification | it states which recognized reason applies |
export type Classes = {
  known: boolean;
  dismissing: Outcome[];
  dismisses: (outcome?: string) => boolean;
  hidesRisk: (outcome?: string) => boolean;
  dated: (outcome?: string) => boolean;
  needsJustification: (outcome?: string) => boolean;
};

// The classes over one published list. A word the list does not hold is in
// none of them, and the server is the one to refuse it.
export function classesOf(published: readonly Claims[] | null | undefined): Classes {
  const by = new Map((published ?? []).map((each) => [each.outcome as string, each]));
  const has = (field: "hides_risk" | "dated" | "needs_justification") => (outcome?: string) =>
    by.get(outcome ?? "")?.[field] ?? false;
  const dismissing = (published ?? []).filter((each) => each.dismisses).map((each) => each.outcome);
  return {
    known: by.size > 0,
    dismissing,
    dismisses: (outcome) => (dismissing as string[]).includes(outcome ?? ""),
    hidesRisk: has("hides_risk"),
    dated: has("dated"),
    needsJustification: has("needs_justification"),
  };
}

// The classes the server published for this session, read from the answer
// every screen already loads.
export function useOutcomes(): Classes {
  const published = useWho().data?.outcomes;
  return useMemo(() => classesOf(published), [published]);
}
