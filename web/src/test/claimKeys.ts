// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Every query a change to a claim moves, sorted: the review acts in
// claims.test.tsx and the edits in mutations.test.tsx both settle it.
export const EVERY_CLAIM_KEY = [
  "advisory",
  "advisory-document",
  "advisory-releases",
  "claim",
  "comments",
  "decided",
  "decision",
  "finding",
  "findings",
  "home",
  "my-claims",
  "queue",
].sort();
