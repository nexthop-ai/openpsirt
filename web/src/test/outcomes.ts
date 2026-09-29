// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Claims } from "../ui/outcomes";

// What the server publishes about each outcome, as a session answer carries
// it, for a test standing in for the server. The server's own test holds the
// rule itself.
export const PUBLISHED: Claims[] = [
  {
    outcome: "affected",
    hides_risk: false,
    dated: false,
    needs_justification: false,
    dismisses: false,
  },
  {
    outcome: "not-applicable",
    hides_risk: true,
    dated: false,
    needs_justification: true,
    dismisses: true,
  },
  {
    outcome: "mismatched",
    hides_risk: true,
    dated: false,
    needs_justification: true,
    dismisses: true,
  },
  {
    outcome: "deferred",
    hides_risk: true,
    dated: true,
    needs_justification: false,
    dismisses: false,
  },
  {
    outcome: "wont-fix",
    hides_risk: true,
    dated: false,
    needs_justification: false,
    dismisses: true,
  },
  {
    outcome: "already-fixed",
    hides_risk: true,
    dated: false,
    needs_justification: false,
    dismisses: true,
  },
  {
    outcome: "upgrade-needed",
    hides_risk: true,
    dated: true,
    needs_justification: false,
    dismisses: false,
  },
  {
    outcome: "patch-needed",
    hides_risk: true,
    dated: true,
    needs_justification: false,
    dismisses: false,
  },
];
