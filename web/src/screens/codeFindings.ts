// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type {
  CodeFindingOutcome,
  CodeFindingReason,
  SuppressionRuleState,
  CodeFindingState,
} from "../api/codeFindings";

// The words for what the server says about code findings. Keyed by the generated
// unions, so a word the server adds is a compile error here until it has one.

export const CODE_FINDING_STATES: Record<CodeFindingState, string> = {
  open: "Open",
  "no-longer-detected": "No longer detected",
  fixed: "Fixed",
  dismissed: "Dismissed",
  "not-security": "Not a security issue",
  confirmed: "Confirmed",
  "recorded-as-flaw": "Recorded as a flaw",
};

// The chip each state is drawn as.
export const CODE_FINDING_TONES: Record<CodeFindingState, string> = {
  open: "open",
  "no-longer-detected": "lapsed",
  fixed: "closed",
  dismissed: "agreed",
  "not-security": "agreed",
  confirmed: "bad",
  "recorded-as-flaw": "agreed",
};

export const CODE_FINDING_REASONS: Record<CodeFindingReason, string> = {
  false_positive: "False positive",
  wont_fix: "Won't fix",
  used_in_tests: "Used only in tests",
  mitigated: "Mitigated",
};

const RULE_STATES: Record<SuppressionRuleState, string> = {
  proposed: "Waiting for approval",
  "in-force": "In force",
  outgrown: "Outgrown",
  "needs-path": "Needs a path",
  retired: "Retired",
};

// Hover text for a rule state that needs it.
export const RULE_STATE_HINTS: Partial<Record<SuppressionRuleState, string>> = {
  outgrown:
    "It covers many more code findings than when it was approved. Approve it again or retire it.",
  "needs-path": "Its rule finds memory or injection flaws, so it dismisses nothing without a path.",
};

// The outcomes a code finding takes, in the order the form offers them.
export const CODE_FINDING_OUTCOMES: CodeFindingOutcome[] = [
  "confirmed",
  "dismissed",
  "not-security",
];

// A code finding's state in words. A word this does not know is shown as it arrived.
export function stateSaid(state?: string): string {
  return state && Object.hasOwn(CODE_FINDING_STATES, state)
    ? CODE_FINDING_STATES[state as CodeFindingState]
    : (state ?? "");
}

// A rule state in words, the same way.
export function ruleStateSaid(state?: string): string {
  return state && Object.hasOwn(RULE_STATES, state)
    ? RULE_STATES[state as SuppressionRuleState]
    : (state ?? "");
}

// A reason in words, the same way.
export function reasonSaid(reason?: string): string {
  return reason && Object.hasOwn(CODE_FINDING_REASONS, reason)
    ? CODE_FINDING_REASONS[reason as CodeFindingReason]
    : (reason ?? "");
}

// Where a result is, as a reader names it: the file and the line.
export function located(path?: string, line?: number): string {
  if (!path) return "";
  return line ? `${path}:${line}` : path;
}
