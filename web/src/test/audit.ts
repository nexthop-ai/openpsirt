// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";

// One decision as the audit log lists it: one occurrence of one issue at one
// component, approved and standing, with what is named replaced.
export function auditDecision(
  over: Partial<Body<"AuditedDecisionBody">> = {},
): Body<"AuditedDecisionBody"> {
  return {
    decision: 7,
    issue: "CVE-2026-1",
    issues: 1,
    product: "sonic",
    products: 1,
    component: "libnl",
    version: "3.7",
    components: 1,
    rows: 1,
    occurrences: 1,
    outcome: "not-applicable",
    reasoning: "Never reached.",
    state: "approved",
    states: { proposed: 0, approved: 1, withdrawn: 0, lapsed: 0 },
    standing: 1,
    proposed_by: "bob",
    proposed_at: "2026-09-01T00:00:00Z",
    approvals: [],
    two_people: false,
    ...over,
  };
}
