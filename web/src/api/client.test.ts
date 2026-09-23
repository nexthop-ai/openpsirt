// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import { csrfCookie } from "./client";

// The `__Host-` prefix is the only thing stopping a sibling host under the
// same registrable domain writing a cookie this deployment then reads. Reading
// whichever name came first gave that away: two cookies of equal path length
// are ordered by when they were created, so one planted first was the one
// sent, every write was refused against the value bound to the session, and
// nothing in the page said why.
// jsdom's own cookie jar orders by its own rules, so the two names are put in
// the order under test directly. What is being pinned is which of two the
// reader prefers, not how a browser stores them.
function set(...pairs: string[]) {
  Object.defineProperty(document, "cookie", { value: pairs.join("; "), configurable: true });
}

afterEach(() => {
  Object.defineProperty(document, "cookie", { value: "", configurable: true });
});

describe("which CSRF cookie is echoed", () => {
  it("prefers the prefixed one, whichever was written first", () => {
    set("openpsirt_csrf=planted", "__Host-openpsirt_csrf=ours");
    expect(csrfCookie()).toBe("ours");
    set("__Host-openpsirt_csrf=ours", "openpsirt_csrf=planted");
    expect(csrfCookie()).toBe("ours");
  });

  it("takes the bare one where there is no prefixed one", () => {
    // A deployment served without TLS holds only this name: a browser refuses
    // the prefix over plain HTTP, so dropping the fallback would break every
    // write there.
    set("openpsirt_csrf=plain");
    expect(csrfCookie()).toBe("plain");
  });

  it("decodes what it finds, and passes on what will not decode", () => {
    set("__Host-openpsirt_csrf=a%20b");
    expect(csrfCookie()).toBe("a b");
    // A malformed escape throws out of `decodeURIComponent`, and this runs in
    // the middleware every write goes through — so one bad cookie set by
    // anything on this host failed every write in the application.
    set("__Host-openpsirt_csrf=%E0%A4%A");
    expect(() => csrfCookie()).not.toThrow();
    expect(csrfCookie()).toBe("%E0%A4%A");
  });

  it("answers with nothing where neither is set", () => {
    set("");
    expect(csrfCookie()).toBe("");
  });
});
