// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { label, waiting } from "./notices";

// The two decisions the notification area makes for itself, tested apart from
// the drawing.
//
// The interface as a whole has one test file for several thousand lines, and
// that is worth saying plainly rather than leaving implied: `tsc` and a
// type-checked client prove the screens compile against the shapes the server
// sends, and nothing proves what they say. These are the pieces where saying
// the wrong thing is a defect rather than a matter of taste.
describe("what a notification is called", () => {
  it("says what happened in words rather than the word a machine matches on", () => {
    expect(label("assigned")).toBe("assigned to you");
    expect(label("sent-back")).toBe("rejected");
    expect(label("build-quiet")).toBe("not being scanned");
    expect(label("inventory-moved")).toBe("a build's contents changed sharply");
    expect(label("obligation-open")).toBe("window after an attack running");
    expect(label("obligation-near")).toBe("window after an attack ending soon");
    expect(label("obligation-passed")).toBe("window after an attack passed");
    // The one of the ten this list left out.
    expect(label("critical-on-release")).toBe("critical on a release");
    // Each of the four staleness conditions says what has stopped rather than
    // what took place; a row that read "claim-waiting" is the word a machine
    // matches on.
    expect(label("claim-waiting")).toBe("waiting for a second person");
    expect(label("sent-back-waiting")).toBe("sent back and not revised");
    expect(label("deferral-ending")).toBe("deferral running out");
    expect(label("queue-untaken")).toBe("sitting in a team queue");
    expect(label("approval-undone")).toBe("agreement taken back");
    expect(label("approval-withdrawn")).toBe("agreed claim changed");
    expect(label("claim-lapsed")).toBe("stopped applying");
  });

  it("shows a kind it does not know rather than hiding it", () => {
    // A server that grows a kind before this does should leave somebody
    // reading something unfamiliar, not a blank row where a notice was.
    expect(label("something-new")).toBe("something-new");
    expect(label(undefined)).toBe("");
  });
});

describe("the count on the way in", () => {
  it("is a number while there is a small number of them", () => {
    expect(waiting(0)).toBe("·");
    expect(waiting(1)).toBe("1");
    expect(waiting(99)).toBe("99");
  });

  it("stops counting past what fits, rather than widening the control", () => {
    expect(waiting(100)).toBe("99+");
    expect(waiting(4821)).toBe("99+");
  });

  it("never renders a negative or fractional count", () => {
    // The total comes from the server. A dot is the honest answer to a number
    // that cannot be drawn, and it is what nothing-waiting already looks like.
    expect(waiting(-3)).toBe("·");
    expect(waiting(Number.NaN)).toBe("·");
    // A fractional one, which is what the name promises and no input
    // supplied: without it the rounding can be deleted and a count renders
    // as "2.5".
    expect(waiting(2.5)).toBe("2");
    expect(waiting(0.5)).toBe("·");
  });
});
