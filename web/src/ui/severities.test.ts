// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { BANDS, BELOW_LOW, ROLLED, bandOf, isBand, ratedAs } from "./severities";

// One nothing, drawn one way. A finding whose vulnerability carries no
// severity was counted as a medium by the chart, drawn as a low by the badge,
// given a low's stripe by the card and its own band by the tree strip — four
// answers about the same row, on the same screen.
describe("what an unrated finding is drawn as", () => {
  it("keeps the four that are rated", () => {
    for (const band of BANDS) expect(bandOf(band)).toBe(band);
  });

  it("gives every unrated shape the one word the split counts under", () => {
    // The server rolls what nobody rated into "unrated" on the wire, so a
    // screen drawing anything else shows a split that does not sum to the
    // count printed beside it.
    expect(bandOf(undefined)).toBe("unrated");
    expect(bandOf(null)).toBe("unrated");
    expect(bandOf("")).toBe("unrated");
    expect(bandOf("unknown")).toBe("unrated");
    expect(bandOf("whatever a producer invented")).toBe("unrated");
  });

  it("puts a rating below low in the low band, because the server does", () => {
    // Somebody looked and said it is not worth much, which is not the same
    // statement as nobody having looked. `rating.BandExpr` puts both of these
    // words in the low band and `SeverityScore` gives them a low's score, so
    // a row drawn as unrated here disagreed with everything that sorted it.
    for (const word of BELOW_LOW) expect(bandOf(word)).toBe("low");
  });

  it("says what was rated, which is not always the band", () => {
    for (const band of BANDS) expect(ratedAs(band)).toBe(band);
    for (const word of BELOW_LOW) expect(ratedAs(word)).toBe(word);
    for (const nothing of ["", "unknown", undefined, null]) {
      expect(ratedAs(nothing)).toBe("unrated");
    }
  });

  it("answers with a word the roll-up has a place for", () => {
    for (const word of ["", "unknown", "negligible", ...BANDS]) {
      expect(ROLLED as readonly string[]).toContain(bandOf(word));
    }
  });

  it("is the test the class name is chosen by, not a second one", () => {
    // `isBand` is false for "unrated", which is why a badge that asked it a
    // second time drew the class of a low while reading "Unrated".
    expect(isBand("unrated")).toBe(false);
    expect(bandOf("unrated")).toBe("unrated");
  });
});
