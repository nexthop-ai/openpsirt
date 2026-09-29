// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { paths } from "../api/schema";

// Why a claim waits in the review queue, in the server's own words.
export type Reason = NonNullable<
  NonNullable<paths["/v1/review-queue"]["get"]["parameters"]["query"]>["reason"]
>;

// The three lists the queue holds, in the order the tabs offer them, with the
// words each is drawn in.
type Words = { reason: Reason; tab: string; empty: string; stated: string };

const APPROVAL: Words = {
  reason: "approval",
  tab: "To approve",
  empty: "A claim needing a second person would appear here.",
  stated: "Pending approval",
};

export const REASONS: Words[] = [
  APPROVAL,
  {
    reason: "expired-deferral",
    tab: "Expired deferrals",
    empty: "A deferral whose date has passed would appear here.",
    stated: "Deferral expired",
  },
  {
    reason: "missed-fix-date",
    tab: "Missed fix dates",
    empty: "A promised upgrade or patch whose date passed with the finding open would appear here.",
    stated: "Fix date missed",
  },
];

// The words one list is drawn in.
export function wordsFor(reason: Reason): Words {
  return REASONS.find((each) => each.reason === reason) ?? APPROVAL;
}

// The list the address names. Anything else is the approvals, which is what
// the queue opens on.
export function queueReason(params: URLSearchParams): Reason {
  const asked = params.get("reason");
  return REASONS.find((each) => each.reason === asked)?.reason ?? "approval";
}

// What a dated claim promised, as a card names it: "Upgrade to 3.0.15 by
// 2026-09-01", "Patch by 2026-09-01", "Deferred until 2026-09-01". Empty for an
// outcome that carries no date.
export function promised(claim: {
  outcome: string;
  upgradeTo: string;
  committedTo: string;
  deferredUntil: string;
}): string {
  switch (claim.outcome) {
    case "upgrade-needed":
      return claim.upgradeTo
        ? `Upgrade to ${claim.upgradeTo} by ${claim.committedTo}`
        : `Upgrade by ${claim.committedTo}`;
    case "patch-needed":
      return `Patch by ${claim.committedTo}`;
    case "deferred":
      return `Deferred until ${claim.deferredUntil}`;
    default:
      return "";
  }
}
