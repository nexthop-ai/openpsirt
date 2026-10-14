// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { happenedOf, stripeOf } from "./stripe";

// The claim page and the finding screen draw the same stripe for the same
// claim, because both ask this.
describe("a claim's stripe", () => {
  it("is neutral for a withdrawn claim", () => {
    expect(stripeOf("withdrawn", true)).toBe("");
    expect(stripeOf(happenedOf("withdrawn", false), true)).toBe("");
  });

  it("reads as in force for a proposed claim nothing waits on", () => {
    expect(stripeOf("waiting", false)).toBe("approved");
    expect(stripeOf(happenedOf("proposed", false), false)).toBe("approved");
  });

  it("is pending while a second person is needed or the claim is still argued", () => {
    expect(stripeOf("waiting", true)).toBe("pending");
    expect(stripeOf("sent-back", true)).toBe("pending");
    expect(stripeOf("undone", true)).toBe("pending");
    expect(stripeOf("mixed", true)).toBe("pending");
    expect(stripeOf(happenedOf("proposed", true), true)).toBe("pending");
  });

  it("is in force once agreed and lapsed once it stopped applying", () => {
    expect(stripeOf("approved", true)).toBe("approved");
    expect(stripeOf("lapsed", true)).toBe("lapsed");
    expect(stripeOf(happenedOf("approved", false), true)).toBe("approved");
    expect(stripeOf(happenedOf("lapsed", false), true)).toBe("lapsed");
  });

  it("is neutral where nothing says what became of it", () => {
    expect(stripeOf(undefined, true)).toBe("");
    expect(stripeOf(happenedOf("", false), true)).toBe("");
  });
});
