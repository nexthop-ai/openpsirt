// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import {
  forgetForward,
  forwardable,
  rememberForward,
  returningHere,
  signedOutHere,
} from "./SignIn";

function at(path: string, search = "") {
  window.history.replaceState({}, "", path + search);
}

afterEach(() => at("/"));

describe("where a sign-in comes back to", () => {
  it("carries the screen somebody was on", () => {
    at("/products/sonic/streams/master/variants/broadcom/findings");
    expect(returningHere()).toBe(
      "?return=%2Fproducts%2Fsonic%2Fstreams%2Fmaster%2Fvariants%2Fbroadcom%2Ffindings",
    );
  });

  it("carries the filters that were set with it", () => {
    // A findings list is its filters. Coming back to the same path with none
    // of them is coming back to a different screen.
    at(
      "/products/sonic/streams/master/variants/broadcom/findings",
      "?state=undecided&severity=high",
    );
    expect(returningHere()).toContain("%3Fstate%3Dundecided%26severity%3Dhigh");
  });

  it("carries nothing from the home page, which is where a sign-in lands anyway", () => {
    at("/");
    expect(returningHere()).toBe("");
  });

  it("escapes what it carries, so the address cannot end the parameter early", () => {
    at("/products/a&b=c/streams");
    const carried = returningHere();
    expect(carried).not.toContain("&b=");
    expect(carried).toBe("?return=%2Fproducts%2Fa%26b%3Dc%2Fstreams");
  });
});

describe("sending somebody straight on to the only provider", () => {
  afterEach(() => {
    forgetForward();
    at("/");
  });

  it("forwards where there is one way in and nothing to read", () => {
    expect(forwardable(1, false)).toBe(true);
  });

  it("draws the list where there is a choice to make", () => {
    // Two providers is a decision somebody has to take, so the screen is the
    // point rather than a stop on the way.
    expect(forwardable(2, false)).toBe(false);
    // And none configured has nothing to forward to.
    expect(forwardable(0, false)).toBe(false);
  });

  it("does not forward over the screen somebody is still on", () => {
    // The resuming offer is drawn over live work after a session ended.
    // Forwarding takes them away from a screen they can still read.
    expect(forwardable(1, true)).toBe(false);
  });

  it("does not forward at the address a sign-out actually lands on", () => {
    // The provider still holds its own session, so forwarding here signs them
    // back in and makes signing out impossible. Asserted against the value the
    // sign-out button navigates to rather than one retyped here, so that
    // changing one side without the other fails.
    const [path, query] = signedOutHere.split("?");
    at(path ?? "/", query ? "?" + query : "");
    expect(forwardable(1, false)).toBe(false);
  });

  it("does not forward after a sign-out once the address is gone", () => {
    // Pressing Back leaves the marker behind but not the address. The tab is
    // marked as well, because the session at the provider outlives both.
    rememberForward();
    at("/findings");
    expect(forwardable(1, false)).toBe(false);
  });

  it("does not forward twice in one tab", () => {
    // Somebody who authenticates and was granted nothing is refused, and the
    // refusal is an API answer rather than a screen. Coming back has to offer
    // the way in rather than send them round again.
    expect(forwardable(1, false)).toBe(true);
    rememberForward();
    expect(forwardable(1, false)).toBe(false);
    // And signing in successfully clears it, so the next one forwards.
    forgetForward();
    expect(forwardable(1, false)).toBe(true);
  });
});
