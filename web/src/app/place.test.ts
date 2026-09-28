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
    window.sessionStorage.setItem(
      "openpsirt.place",
      JSON.stringify({ "/a": { y: "not a number", at: 1 }, "/b": { y: -4000, at: 2 } }),
    );
    expect(placeOf("/a")).toBe(0);
    expect(placeOf("/b")).toBe(0);
    window.sessionStorage.setItem("openpsirt.place", "not json");
    expect(placeOf("/a")).toBe(0);
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
    const kept = Object.keys(JSON.parse(window.sessionStorage.getItem("openpsirt.place") ?? "{}"));
    expect(kept.length).toBe(12);
    // The most recent is the one worth having: it is the list somebody just
    // came from.
    expect(placeOf("/list-39")).toBe(390);
    expect(placeOf("/list-28")).toBe(280);
    expect(placeOf("/list-27")).toBe(0);
  });

  it("keeps a page marked again as recent, whatever order it was first marked in", () => {
    markPlace("/first", 50);
    for (let i = 0; i < 11; i++) markPlace(`/list-${i}`, i * 10);
    markPlace("/first", 60);
    markPlace("/one-more", 70);
    expect(placeOf("/first")).toBe(60);
    expect(placeOf("/list-0")).toBe(0);
  });
});
