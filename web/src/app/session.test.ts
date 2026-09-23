// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";
import { signOut } from "./session";
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
        return Promise.resolve();
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

  it("marks the forward and leaves, whether or not the server answered", async () => {
    // Both halves, because either alone signs somebody straight back in where
    // there is one provider: the address is lost the moment somebody presses
    // Back, and the tab's mark is what survives it.
    for (const end of [
      () => Promise.resolve(),
      () => Promise.reject(new Error("the network went away")),
    ]) {
      window.sessionStorage.clear();
      const went = vi.fn();
      await signOut(end, went);
      expect(went).toHaveBeenCalledTimes(1);
      expect(String(went.mock.calls[0]?.[0])).toContain("signed-out");
      expect(window.sessionStorage.length, "nothing marks the forward in this tab").toBeGreaterThan(
        0,
      );
    }
  });
});
