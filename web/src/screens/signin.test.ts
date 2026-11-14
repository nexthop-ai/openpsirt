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
    at("/products/sonic/branches-and-tags/master/variants/broadcom/findings");
    expect(returningHere()).toBe(
      "?return=%2Fproducts%2Fsonic%2Fbranches-and-tags%2Fmaster%2Fvariants%2Fbroadcom%2Ffindings",
    );
  });

  it("carries the filters that were set with it", () => {
    // A findings list is its filters. Coming back to the same path with none
    // of them is coming back to a different screen.
    at(
      "/products/sonic/branches-and-tags/master/variants/broadcom/findings",
      "?state=undecided&severity=high",
    );
    expect(returningHere()).toContain("%3Fstate%3Dundecided%26severity%3Dhigh");
  });

  it("carries nothing from the address a refused sign-in lands on", () => {
    // Coming back there after signing in with another account would draw the
    // home page under an address that says they were refused.
    at("/", "?no-access");
    expect(returningHere()).toBe("");
    // However the marker is spelled, as the screen reads it.
    at("/", "?no-access=&x=1");
    expect(returningHere()).toBe("");
    // A screen's own query carrying the word keeps its place.
    at("/findings", "?no-access");
    expect(returningHere()).toBe("?return=%2Ffindings%3Fno-access");
  });

  it("carries nothing from the address a sign-out lands on", () => {
    const [path, query] = signedOutHere.split("?");
    at(path ?? "/", query ? "?" + query : "");
    expect(returningHere()).toBe("");
  });

  it("carries nothing from the home page, which is where a sign-in lands anyway", () => {
    at("/");
    expect(returningHere()).toBe("");
  });

  it("escapes what it carries, so the address cannot end the parameter early", () => {
    at("/products/a&b=c/branches-and-tags");
    const carried = returningHere();
    expect(carried).not.toContain("&b=");
    expect(carried).toBe("?return=%2Fproducts%2Fa%26b%3Dc%2Fbranches-and-tags");
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

  it("does not forward at the address a refused sign-in lands on", () => {
    // The provider still holds the account it refused, so forwarding would
    // refuse it again in a loop. The server redirects every refused sign-in
    // to this literal address (internal/httpapi/signin.go), so it is written
    // out here rather than read back from the screen.
    at("/", "?no-access");
    expect(forwardable(1, false)).toBe(false);
    // Only there: a screen's own query carrying the word forwards as usual.
    at("/findings", "?no-access");
    expect(forwardable(1, false)).toBe(true);
  });

  it("does not forward after a sign-out once the address is gone", () => {
    // Pressing Back leaves the marker behind but not the address. The tab is
    // marked as well, because the session at the provider outlives both.
    rememberForward();
    at("/findings");
    expect(forwardable(1, false)).toBe(false);
  });

  it("does not forward twice in one tab", () => {
    // A forward that comes back without a session offers the way in.
    expect(forwardable(1, false)).toBe(true);
    rememberForward();
    expect(forwardable(1, false)).toBe(false);
    // And signing in successfully clears it, so the next one forwards.
    forgetForward();
    expect(forwardable(1, false)).toBe(true);
  });
});
