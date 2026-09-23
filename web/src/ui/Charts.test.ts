// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { folded } from "./Charts";

// The four bands, folded the way the server folds them.
//
// This is a second copy of a rule the server owns — the same CASE the severity
// filter, the triage floor, the order and the deadline are all worked out
// from — and the two have already disagreed once: "unknown" was counted here
// as a low and is a medium everywhere the server looks at it, so Home said
// 1,415 low where the list agreed on 38 and a thousand findings were one thing
// on one screen and another on the next.
//
// A second copy cannot be removed — the server does not send the folding, it
// sends the words — so what it gets instead is a test at every boundary.
describe("folding a severity the way the server folds it", () => {
  it("keeps the two bands that are their own word", () => {
    expect(folded({ critical: 3, high: 5 })).toEqual({
      critical: 3,
      high: 5,
      medium: 0,
      low: 0,
    });
  });

  it("folds the three words below the line into one", () => {
    // Three words the server treats alike, and a screen that split them would
    // show three small numbers where the list shows one.
    expect(folded({ low: 1, negligible: 2, none: 4 })).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 7,
    });
  });

  it("treats a rating with no word as a medium rather than dismissing it", () => {
    // The disagreement that cost 1,377 findings their band. A rating nobody
    // has scored is a medium everywhere the server looks at it, because a
    // deadline is set from it and dismissing it as a low sets the wrong one.
    expect(folded({ medium: 1, unknown: 2, "": 3, whatever: 4 })).toEqual({
      critical: 0,
      high: 0,
      medium: 10,
      low: 0,
    });
  });

  it("names all four bands even where nothing is in them", () => {
    // A chart with a missing key draws a gap rather than a zero, and a band
    // with nothing in it is a fact worth drawing.
    expect(folded({})).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
  });
});
