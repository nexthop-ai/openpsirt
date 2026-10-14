// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";

// What became of a claim, in the server's words.
export type Happened = Body<"ClaimDetail">["happened"];

// The stripe down a claim's card, which says its state before anybody reads a
// word of it, on the claim page and on the finding screen alike.
//
// | Stripe | Means |
// |---|---|
// | pending | waiting on a second person, or still argued: sent back, an agreement undone, rows that ended several ways |
// | approved | in force: agreed to, or proposed where nothing waits on a second person |
// | lapsed | stopped applying under it |
// | none | withdrawn by its proposer, which ends it without standing either way |
type Stripe = "pending" | "approved" | "lapsed" | "";

export function stripeOf(happened: Happened | undefined, needsApproval: boolean): Stripe {
  switch (happened) {
    case undefined:
    case "withdrawn":
      return "";
    case "approved":
      return "approved";
    case "lapsed":
      return "lapsed";
    case "waiting":
      return needsApproval ? "pending" : "approved";
    default:
      return "pending";
  }
}

// A claim's stored state as a word of what became of it, for a screen that
// holds the state rather than the server's reading of it.
export function happenedOf(state: string | undefined, sentBack: boolean): Happened | undefined {
  switch (state) {
    case "proposed":
      return sentBack ? "sent-back" : "waiting";
    case "approved":
    case "withdrawn":
    case "lapsed":
      return state;
  }
  return undefined;
}
