// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";

// Every outcome the server records, read from the published API document so a
// word the server adds is a compile error here until it has an entry.
export type Outcome = NonNullable<Body<"DisposedBody">["outcome"]>;

// What each outcome claims, in the terms the server classifies it by.
//
// | Field | Means |
// |---|---|
// | hidesRisk | recording it takes the issue out of the working queue |
// | dated | it stores a date: a review date, or when promised work lands |
// | needsJustification | it states which recognized reason applies |
const CLAIMS: Record<Outcome, { hidesRisk: boolean; dated: boolean; needsJustification: boolean }> =
  {
    affected: { hidesRisk: false, dated: false, needsJustification: false },
    "not-applicable": { hidesRisk: true, dated: false, needsJustification: true },
    mismatched: { hidesRisk: true, dated: false, needsJustification: true },
    deferred: { hidesRisk: true, dated: true, needsJustification: false },
    "wont-fix": { hidesRisk: true, dated: false, needsJustification: false },
    "already-fixed": { hidesRisk: true, dated: false, needsJustification: false },
    "upgrade-needed": { hidesRisk: true, dated: true, needsJustification: false },
    "patch-needed": { hidesRisk: true, dated: true, needsJustification: false },
  };

const OUTCOMES = Object.keys(CLAIMS) as Outcome[];

// The outcomes that close the question: they hide risk and carry no date, so
// nothing later re-opens them. The same rule the server counts and filters by.
export const DISMISSING: Outcome[] = OUTCOMES.filter(
  (each) => CLAIMS[each].hidesRisk && !CLAIMS[each].dated,
);

// Whether a claim of this outcome has to say which recognized reason applies.
// A word this does not know needs none, and the server is the one to refuse it.
export function needsJustification(outcome?: string): boolean {
  return Object.hasOwn(CLAIMS, outcome ?? "") && CLAIMS[outcome as Outcome].needsJustification;
}

// Whether a word is one of the dismissing outcomes.
export function dismisses(outcome?: string): boolean {
  return (DISMISSING as string[]).includes(outcome ?? "");
}
