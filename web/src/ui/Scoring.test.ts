import { describe, expect, it } from "vitest";
import { carriedTo, metricsOf, read, vectorOf, versionOf } from "./Scoring";

const WHOLE = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" };
const WHOLE_FOUR = {
  AV: "N",
  AC: "L",
  AT: "N",
  PR: "N",
  UI: "N",
  VC: "H",
  VI: "H",
  VA: "H",
  SC: "H",
  SI: "H",
  SA: "H",
};

// Composing a CVSS base vector, which is what gets stored and what every
// deadline is worked out from. The module is a `.tsx` file, which is no
// barrier to a `.ts` test: a `.tsx` module is importable from one, and six
// already do it.
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

  it("keeps the version a version 4 vector was recorded under", () => {
    expect(vectorOf(WHOLE_FOUR, versionOf("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N"))).toBe(
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    );
  });

  it("composes under 3.1 where nothing says otherwise, which is not the newest", () => {
    // A published advisory is a CSAF 2.0 document, which has a field for a
    // version 3 score and none for a version 4 one. The default is the scheme
    // the document can carry; version 4 is a choice somebody makes.
    expect(versionOf("")).toBe("CVSS:3.1");
  });

  it("reads an unversioned vector for the generation its metrics belong to", () => {
    // Stamping the default on it instead labels a version 4 vector as version
    // 3, which is a score under a formula that never produced it.
    expect(versionOf("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBe("CVSS:4.0");
    expect(versionOf("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe("CVSS:3.1");
    // Neither generation is named by the metrics both of them share.
    expect(versionOf("AV:N/AC:L")).toBe("CVSS:3.1");
  });

  it("asks eleven metrics under version 4 and eight under version 3", () => {
    // Not the eight with three added: what version 3 asks once about impact,
    // version 4 asks twice, and the two it shares with version 3 are asked
    // with different words.
    expect(metricsOf("CVSS:3.1").map((m) => m.key)).toEqual([
      "AV",
      "AC",
      "PR",
      "UI",
      "S",
      "C",
      "I",
      "A",
    ]);
    expect(metricsOf("CVSS:4.0").map((m) => m.key)).toEqual([
      "AV",
      "AC",
      "AT",
      "PR",
      "UI",
      "VC",
      "VI",
      "VA",
      "SC",
      "SI",
      "SA",
    ]);
  });

  it("composes nothing until every metric of the scheme it is on is answered", () => {
    // The eight a version 3 vector needs are not enough for a version 4 one,
    // and composing them under version 4 would name a vector the scheme has
    // no formula for.
    for (const metric of Object.keys(WHOLE_FOUR)) {
      const short = { ...WHOLE_FOUR };
      delete (short as Record<string, string>)[metric];
      expect(vectorOf(short, "CVSS:4.0"), `${metric} unanswered`).toBe("");
    }
    expect(vectorOf(WHOLE, "CVSS:4.0")).toBe("");
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

describe("what survives a change of scheme", () => {
  it("keeps an answer the new scheme also offers", () => {
    // Four metrics are asked by both generations, and three of them offer the
    // same answers. Dropping those would make somebody answer again to say
    // the same thing.
    expect(carriedTo("CVSS:4.0", { AV: "N", AC: "H", PR: "L", S: "U", C: "H" })).toEqual({
      AV: "N",
      AC: "H",
      PR: "L",
    });
  });

  it("drops an answer the new scheme does not offer, metric or value", () => {
    // User interaction is asked by both and answered differently: version 3
    // asks whether a person has to act, version 4 asks how. Carried by name
    // alone, Required composes a version 4 vector the scoring refuses — and
    // the metric reads as answered while its control shows nothing.
    expect(carriedTo("CVSS:4.0", { AV: "N", UI: "R" })).toEqual({ AV: "N" });
    expect(carriedTo("CVSS:3.1", { AV: "N", UI: "P" })).toEqual({ AV: "N" });
    expect(carriedTo("CVSS:3.1", { AV: "N", UI: "A" })).toEqual({ AV: "N" });
    // The one answer it does carry, because both generations offer it.
    expect(carriedTo("CVSS:4.0", { UI: "N" })).toEqual({ UI: "N" });
  });

  it("composes nothing from an answer it dropped", () => {
    // The whole of why the value matters: eleven metrics answered with a
    // version 3 user interaction is not a version 4 vector.
    const carried = carriedTo("CVSS:4.0", { ...WHOLE_FOUR, UI: "R" });
    expect(carried.UI).toBeUndefined();
    expect(vectorOf(carried, "CVSS:4.0")).toBe("");
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
