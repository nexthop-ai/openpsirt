// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The words of the notification area, apart from its drawing.
//
// Here rather than inside the component so both can be tested without a DOM:
// these two are where saying the wrong thing is a defect rather than a matter
// of taste.

import type { Body } from "../api/client";
import { own } from "./own";

// Every kind of notification the server sends, from the published document.
export type Kind = Body<"NotificationBody">["kind"];

// The words the server sends are for a machine to match on; these are for
// somebody to read. Keyed on the published kinds, so a kind the server adds
// is a compile error here until it has words.
const WORDS: Record<Kind, string> = {
  assigned: "assigned to you",
  mentioned: "named in a note",
  "sent-back": "rejected",
  "build-quiet": "not being scanned",
  // Somebody who has not signed in for a while, still holding work.
  "holding-absent": "somebody away holding work",
  "critical-on-release": "critical on a release",
  // An embargo's date, arrived or coming, with nothing decided.
  "disclosure-due": "embargo date reached",
  "disclosure-near": "embargo running out",
  // A VEX publisher changed what a standing decision cited. The decision
  // stands; the ground under it moved.
  "statement-revised": "cited statement changed",
  // The four things that are wrong because nothing has happened. Each says
  // what has stopped rather than what took place, which is what makes a row
  // of them read as a list of things to pick up.
  "claim-waiting": "waiting for a second person",
  "sent-back-waiting": "sent back and not revised",
  "deferral-ending": "deferral running out",
  "queue-untaken": "sitting in a team queue",
  // The two outcomes a proposer is told about. Approval is not one of them:
  // it is what they asked for.
  "approval-undone": "agreement taken back",
  // Told to an approver: what they agreed to was changed, so their
  // agreement stopped counting.
  "approval-withdrawn": "agreed claim changed",
  "claim-lapsed": "stopped applying",
  // Two judgments that disagreed met when two issues merged; one stands.
  "merge-superseded": "superseded by a merge",
  "brought-in": "brought into a case",
  disclosed: "disclosed",
  "unanswered-report": "report not answered",
  // The conditions about the deployment rather than about anybody's work,
  // all told to administrators.
  "vulnerability-data-stale": "vulnerability data not moving",
  "risk-unagreed": "hidden with nobody agreeing",
  "pairs-concentrated": "one pair agreeing to most of the work",
  "supplier-silent": "supplier stopped answering",
  // An upload that changed much of what a build is made of. Said as what it
  // was rather than as what it might mean: nothing here knows whether the
  // base image moved or the pipeline broke.
  "inventory-moved": "a build's contents changed sharply",
  // A window after an attack, counted from when it became known, with
  // nobody outside recorded as told. Said as the fact; whether anybody owed
  // anything is not the tool's answer to give.
  "obligation-open": "window after an attack running",
  "obligation-near": "window after an attack ending soon",
  "obligation-passed": "window after an attack passed",
};

// A kind this does not know is shown as it arrived: a server deployed ahead
// of the interface should leave somebody reading something unfamiliar, not a
// blank row where a notice was.
export function label(kind?: string): string {
  return own(WORDS, kind) ?? kind ?? "";
}

// The notifications a destination takes: one kind's words, or "everything"
// for the wildcard the destination is stored with.
export function takes(kind?: Body<"OutboundBody">["kind"]): string {
  return kind === "*" ? "everything" : label(kind);
}

// The count on the control that opens it.
//
// A number rather than a dot, because "three things" and "something" are
// different amounts of interruption and the number is what decides whether
// somebody opens it now or later. Past what fits, it stops counting rather
// than widening — and a total that cannot be drawn at all reads as the same
// nothing an empty list does.
export function waiting(total: number): string {
  if (!Number.isFinite(total) || total < 1) {
    return "·";
  }
  const whole = Math.floor(total);
  return whole > 99 ? "99+" : String(whole);
}
