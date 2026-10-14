// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";
import { mayOf, signedOutBy, signOut } from "./session";
import type { Who } from "./session";
import { belongTo, keep, restore } from "./drafts";

// The sequence a sign-out runs, and its order.
//
// The order is the whole of it: drafts hold triage text, private findings
// included, and text that survived a sign-out would be exposed in a way the
// application itself is not. So they go first, before anything is awaited and
// outside the try — and a sign-out the server never received is exactly the
// case where that matters.
//
// None of it was assertable until the sequence came out of the click handler:
// an anonymous async function on a button is not something a test can reach.
describe("signing out", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    belongTo("oidc:ana");
  });

  it("clears drafts before it asks the server, not after", () => {
    keep("revise:1", "half a justification about something embargoed");
    let clearedFirst = false;
    return signOut(
      () => {
        // Read inside the call the sequence awaits, which is the only place
        // that can tell "before" from "after".
        clearedFirst = restore("revise:1") === "";
        return Promise.resolve(true);
      },
      () => {},
    ).then(() => {
      expect(clearedFirst, "the draft was still there when the server was asked").toBe(true);
      expect(restore("revise:1")).toBe("");
    });
  });

  it("clears drafts even when the server never hears about it", async () => {
    keep("revise:2", "text nobody outside should ever see");
    await signOut(
      () => Promise.reject(new Error("the network went away")),
      () => {},
    );
    expect(restore("revise:2")).toBe("");
  });

  it("marks the forward and leaves once the server has ended the session", async () => {
    // Both halves, because either alone signs somebody straight back in where
    // there is one provider: the address is lost the moment somebody presses
    // Back, and the tab's mark is what survives it.
    const went = vi.fn();
    expect(await signOut(() => Promise.resolve(true), went)).toBe(true);
    expect(went).toHaveBeenCalledTimes(1);
    expect(String(went.mock.calls[0]?.[0])).toContain("signed-out");
    expect(window.sessionStorage.length, "nothing marks the forward in this tab").toBeGreaterThan(
      0,
    );
  });

  it("stays, with drafts cleared, where the server did not end the session", async () => {
    // The server clears the cookie only when it ends the session, so leaving
    // here hands the next person on this browser a live session.
    for (const end of [
      () => Promise.resolve(false),
      () => Promise.reject(new Error("the network went away")),
    ]) {
      keep("revise:3", "text nobody outside should ever see");
      const went = vi.fn();
      expect(await signOut(end, went)).toBe(false);
      expect(went).not.toHaveBeenCalled();
      expect(restore("revise:3")).toBe("");
    }
  });

  it("reads a refusal for want of any session as signed out", () => {
    expect(signedOutBy(204)).toBe(true);
    expect(signedOutBy(401)).toBe(true);
    expect(signedOutBy(503)).toBe(false);
    expect(signedOutBy(500)).toBe(false);
  });
});

// What somebody may do in a product is found whatever capitals the product
// was typed with, as the server finds it.
describe("what somebody may do in a product", () => {
  it("is found whatever the capitals", () => {
    const who = { reach: [{ product: "sonic", may_hide: true }] } as unknown as Who;
    expect(mayOf(who, "SONiC")?.may_hide).toBe(true);
    expect(mayOf(who, "other")).toBeUndefined();
  });
});
