// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from "vitest";
import { forgetPlaces, markPlace, placeOf } from "./place";

beforeEach(() => {
  window.sessionStorage.clear();
});

describe("where somebody was", () => {
  it("gives back the position it was told", () => {
    markPlace("/products/mine/findings?state=undecided", 2075);
    expect(placeOf("/products/mine/findings?state=undecided")).toBe(2075);
  });

  it("knows nothing about a page it was never told about", () => {
    expect(placeOf("/products/mine/findings")).toBe(0);
  });

  it("keeps a position per address, because two lists are two places", () => {
    markPlace("/a", 100);
    markPlace("/b", 900);
    expect(placeOf("/a")).toBe(100);
    expect(placeOf("/b")).toBe(900);
  });

  it("reads an edited value as no position at all", () => {
    // The store is the browser's and a person may write to it. What comes out
    // goes straight into a scroll call, so anything that is not a position is
    // the top of the page rather than an argument nothing checked.
    window.sessionStorage.setItem("openpsirt.place./a", "not a number");
    expect(placeOf("/a")).toBe(0);
    window.sessionStorage.setItem("openpsirt.place./b", "-4000");
    expect(placeOf("/b")).toBe(0);
  });

  it("forgets every page at once", () => {
    markPlace("/a", 100);
    markPlace("/b", 900);
    window.sessionStorage.setItem("openpsirt.scope", "kept");
    forgetPlaces();
    expect(placeOf("/a")).toBe(0);
    expect(placeOf("/b")).toBe(0);
    // And takes nothing else with it: the scope is the session's too and is
    // cleared by whoever owns it.
    expect(window.sessionStorage.getItem("openpsirt.scope")).toBe("kept");
  });

  it("does not grow without bound as somebody reads list after list", () => {
    for (let i = 0; i < 40; i++) markPlace(`/list-${i}`, i * 10);
    let kept = 0;
    for (let i = 0; i < window.sessionStorage.length; i++) {
      if (window.sessionStorage.key(i)?.startsWith("openpsirt.place.")) kept++;
    }
    expect(kept).toBeLessThanOrEqual(12);
    // The most recent is the one worth having: it is the list somebody just
    // came from.
    expect(placeOf("/list-39")).toBe(390);
  });
});
