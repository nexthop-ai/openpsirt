import { describe, expect, it } from "vitest";
import { BANDS, ROLLED, bandOf, isBand } from "./severities";

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
    expect(bandOf("negligible")).toBe("unrated");
    expect(bandOf("none")).toBe("unrated");
    expect(bandOf("whatever a producer invented")).toBe("unrated");
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
