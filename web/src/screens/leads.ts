// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { LeadOutcome, LeadReason, LeadRuleState, LeadState } from "../api/leads";

// The words for what the server says about leads. Keyed by the generated
// unions, so a word the server adds is a compile error here until it has one.

export const LEAD_STATES: Record<LeadState, string> = {
  baseline: "Baseline",
  open: "Open",
  "not-reproduced": "Not reproduced",
  fixed: "Fixed",
  dismissed: "Dismissed",
  "not-security": "Not a security issue",
  confirmed: "Confirmed",
};

// The chip each state is drawn as.
export const LEAD_TONES: Record<LeadState, string> = {
  baseline: "closed",
  open: "open",
  "not-reproduced": "lapsed",
  fixed: "closed",
  dismissed: "agreed",
  "not-security": "agreed",
  confirmed: "bad",
};

export const LEAD_REASONS: Record<LeadReason, string> = {
  false_positive: "False positive",
  wont_fix: "Won't fix",
  used_in_tests: "Used only in tests",
  mitigated: "Mitigated",
};

const RULE_STATES: Record<LeadRuleState, string> = {
  proposed: "Waiting for approval",
  "in-force": "In force",
  outgrown: "Outgrown",
  "needs-path": "Needs a path",
  retired: "Retired",
};

// Hover text for a rule state that needs it.
export const RULE_STATE_HINTS: Partial<Record<LeadRuleState, string>> = {
  outgrown: "It covers many more leads than when it was approved. Approve it again or retire it.",
  "needs-path": "Its rule finds memory or injection flaws, so it dismisses nothing without a path.",
};

// The outcomes a lead takes, in the order the form offers them.
export const LEAD_OUTCOMES: LeadOutcome[] = ["confirmed", "dismissed", "not-security"];

// A lead's state in words. A word this does not know is shown as it arrived.
export function stateSaid(state?: string): string {
  return state && Object.hasOwn(LEAD_STATES, state)
    ? LEAD_STATES[state as LeadState]
    : (state ?? "");
}

// A rule state in words, the same way.
export function ruleStateSaid(state?: string): string {
  return state && Object.hasOwn(RULE_STATES, state)
    ? RULE_STATES[state as LeadRuleState]
    : (state ?? "");
}

// A reason in words, the same way.
export function reasonSaid(reason?: string): string {
  return reason && Object.hasOwn(LEAD_REASONS, reason)
    ? LEAD_REASONS[reason as LeadReason]
    : (reason ?? "");
}

// Where a result is, as a reader names it: the file and the line.
export function located(path?: string, line?: number): string {
  if (!path) return "";
  return line ? `${path}:${line}` : path;
}
