import { describe, expect, it } from "vitest";
import { read, vectorOf, versionOf } from "./Scoring";

const WHOLE = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" };

// Composing a CVSS base vector, which is what gets stored and what every
// deadline is worked out from. Untested until now, and in a `.tsx` file —
// which was easy to read as a tooling limit and was not one: a `.tsx` module
// is importable from a `.ts` test, and six already do it.
describe("what a composed vector says it is", () => {
  it("keeps the version the vector being edited was recorded under", () => {
    // The base formula is the same in 3.0 and 3.1, so the score does not move
    // and the rewrite is silent. What changes is what the vector claims: an
    // assessment recorded under 3.0 that reads as 3.1 after somebody adjusted
    // one metric is a statement nobody made.
    expect(vectorOf(WHOLE, versionOf("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))).toBe(
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    );
    expect(vectorOf(WHOLE, versionOf("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))).toBe(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    );
  });

  it("composes under the newest version where the vector states none it knows", () => {
    // Nothing to keep, so there is nothing to lose by stating the newest: a
    // vector being written from an empty form is being written now.
    expect(versionOf("")).toBe("CVSS:3.1");
    expect(versionOf("AV:N/AC:L")).toBe("CVSS:3.1");
    expect(versionOf("CVSS:4.0/AV:N")).toBe("CVSS:3.1");
  });

  it("composes nothing until all eight metrics are answered", () => {
    // Seven of eight is not a base vector, and a score from it would be a
    // number nobody could reproduce.
    for (const metric of Object.keys(WHOLE)) {
      const short = { ...WHOLE };
      delete (short as Record<string, string>)[metric];
      expect(vectorOf(short, "CVSS:3.1"), `${metric} unanswered`).toBe("");
    }
    expect(vectorOf({}, "CVSS:3.1")).toBe("");
  });

  it("writes the metrics in the order the scheme states them", () => {
    // A vector is compared as a string in places that are not this tool, so
    // the order is part of what it is rather than a matter of presentation.
    expect(vectorOf(WHOLE, "CVSS:3.1")).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  });
});

describe("what a pasted vector is read as", () => {
  it("reads a whole vector back into the metrics it states", () => {
    expect(read("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toEqual(WHOLE);
  });

  it("reads a partial one as only what it names", () => {
    expect(read("CVSS:3.1/AV:N/AC:L")).toEqual({ AV: "N", AC: "L" });
    expect(read("")).toEqual({});
  });

  it("reads it however it was capitalized", () => {
    expect(read("cvss:3.1/av:n/ac:l")).toEqual({ AV: "N", AC: "L" });
  });

  it("keeps the base metrics out of a vector carrying more than base ones", () => {
    // A vector pasted from a scanner carries temporal and environmental
    // metrics beside the eight. Refusing it would make a paste fail for
    // carrying more information than was asked for; the eight are still in it
    // and the extra ones are not ones this composes.
    const pasted = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C";
    const chosen = read(pasted);
    for (const [metric, value] of Object.entries(WHOLE)) {
      expect(chosen[metric], metric).toBe(value);
    }
    // And composing from it writes the base vector alone, so the extra
    // metrics are not carried into something this tool claims to have scored.
    expect(vectorOf(chosen, versionOf(pasted))).toBe(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    );
  });
});
