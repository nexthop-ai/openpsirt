// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Every query a change to a decision moves, sorted: the review acts in
// decisions.test.tsx and the edits in mutations.test.tsx both settle it.
export const EVERY_DECISION_KEY = [
  "advisory",
  "advisory-document",
  "advisory-releases",
  "comments",
  "decided",
  "decision",
  "decision-occurrence",
  "finding",
  "findings",
  "home",
  "code-finding",
  "code-findings",
  "my-decisions",
  "queue",
].sort();
