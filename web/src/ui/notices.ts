// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The words of the notification area, apart from its drawing.
//
// Here rather than inside the component so both can be tested without a DOM:
// these two are where saying the wrong thing is a defect rather than a matter
// of taste.

// The words the server sends are for a machine to match on; these are for
// somebody to read. A kind this does not know is shown as it arrived — a
// server that grows one before the interface does should leave somebody
// reading something unfamiliar, not a blank row where a notice was.
export function label(kind?: string): string {
  switch (kind) {
    case "assigned":
      return "assigned to you";
    case "sent-back":
      return "rejected";
    case "build-quiet":
      return "not being scanned";
    case "critical-on-release":
      return "critical on a release";
    // An upload that changed much of what a build is made of. Said as what it
    // was rather than as what it might mean: nothing here knows whether the
    // base image moved or the pipeline broke.
    case "inventory-moved":
      return "a build's contents changed sharply";
    // A window after an attack, counted from when it became known, with
    // nobody outside recorded as told. Said as the fact; whether anybody owed
    // anything is not the tool's answer to give.
    case "obligation-open":
      return "window after an attack running";
    case "obligation-near":
      return "window after an attack ending soon";
    case "obligation-passed":
      return "window after an attack passed";
    // The conditions about the deployment rather than about anybody's work,
    // all told to administrators. Each is named here, because on these the
    // fallthrough below reads as a tool nobody finished rather than as one
    // the server has grown past.
    case "vulnerability-data-stale":
      return "vulnerability data not moving";
    case "risk-unagreed":
      return "hidden with nobody agreeing";
    case "pairs-concentrated":
      return "one pair agreeing to most of the work";
    case "supplier-silent":
      return "supplier stopped answering";
    // The four things that are wrong because nothing has happened. Each says
    // what has stopped rather than what took place, which is what makes a row
    // of them read as a list of things to pick up.
    case "claim-waiting":
      return "waiting for a second person";
    case "sent-back-waiting":
      return "sent back and not revised";
    case "deferral-ending":
      return "deferral running out";
    case "queue-untaken":
      return "sitting in a team queue";
    // The two outcomes a proposer is told about. Approval is not one of them:
    // it is what they asked for.
    case "approval-undone":
      return "agreement taken back";
    case "claim-lapsed":
      return "stopped applying";
    case "disclosed":
      return "disclosed";
    default:
      return kind ?? "";
  }
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
