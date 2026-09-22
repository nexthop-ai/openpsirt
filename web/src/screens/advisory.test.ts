import { describe, expect, it } from "vitest";
import { missing, nameable, standing, statusLabel } from "./advisory";

describe("an editorial status the interface does not know", () => {
  it("is shown as it arrived rather than crashing the render", () => {
    for (const word of ["constructor", "toString", "valueOf", "__proto__", "hasOwnProperty"]) {
      expect(() => statusLabel(word)).not.toThrow();
      expect(standing(word)).toBeUndefined();
      expect(statusLabel(word)).toBe(word);
    }
  });

  it("is still shown as it arrived for a word nobody has ever used", () => {
    expect(statusLabel("superseded")).toBe("superseded");
    expect(statusLabel(undefined)).toBe("");
  });
});

describe("the three statuses", () => {
  it("each carry a word a reader sees and a sentence saying what it means", () => {
    for (const word of ["draft", "final", "interim"]) {
      const it = standing(word);
      expect(it?.label).toBeTruthy();
      expect(it?.means).toBeTruthy();
      expect(statusLabel(word)).not.toBe(word);
    }
  });

  it("do not tell a reader that an interim document has changed since it went out", () => {
    // A withdrawn agreement reaches interim with nothing a reader acts on
    // having moved, so a sentence about a change is one that is often false.
    expect(standing("interim")?.means).not.toMatch(/chang/i);
  });
});

describe("what has to happen before an advisory goes out", () => {
  it("is a flaw, where it names none", () => {
    expect(missing(0, 0)).toBe("flaws");
  });

  it("is a flaw even where somebody has agreed, because it generates no document", () => {
    expect(missing(0, 2)).toBe("flaws");
  });

  it("is an agreement, where it names a flaw and nobody has agreed", () => {
    expect(missing(3, 0)).toBe("agreement");
  });

  it("is nothing, where it names a flaw and an agreement stands", () => {
    expect(missing(1, 1)).toBe("");
  });
});

describe("the flaws offered for an advisory", () => {
  const rows = [
    { vulnerability: "CVE-2026-1", summary: "one" },
    { vulnerability: "CVE-2026-1", summary: "one, at a second component" },
    { vulnerability: "CVE-2026-2", summary: "two" },
  ];

  it("offer a flaw recorded at two components once", () => {
    expect(nameable(rows, [], "switch").map((one) => one.vulnerability)).toEqual([
      "CVE-2026-1",
      "CVE-2026-2",
    ]);
  });

  it("keep the summary of the first row a flaw arrived on", () => {
    expect(nameable(rows, [], "switch").at(0)?.summary).toBe("one");
  });

  it("leave out what this advisory already names in this product", () => {
    const covers = [{ product: "switch", vulnerability: "CVE-2026-1" }];
    expect(nameable(rows, covers, "switch").map((one) => one.vulnerability)).toEqual([
      "CVE-2026-2",
    ]);
  });

  it("still offer it where the advisory names it in another product", () => {
    // The pair is what an advisory names. The same issue in a second product
    // is a second thing to say, and the releases carrying it differ.
    const covers = [{ product: "router", vulnerability: "CVE-2026-1" }];
    expect(nameable(rows, covers, "switch").map((one) => one.vulnerability)).toEqual([
      "CVE-2026-1",
      "CVE-2026-2",
    ]);
  });

  it("drop a row carrying no identifier rather than offering an empty choice", () => {
    expect(nameable([{ summary: "nameless" }], [], "switch")).toEqual([]);
  });

  it("offer a flaw carrying no summary, with nothing where the summary goes", () => {
    expect(nameable([{ vulnerability: "CVE-2026-3" }], [], "switch")).toEqual([
      { vulnerability: "CVE-2026-3", summary: "" },
    ]);
  });

  it("are not narrowed by a covered entry carrying no identifier", () => {
    expect(
      nameable(rows, [{ product: "switch" }], "switch").map((one) => one.vulnerability),
    ).toEqual(["CVE-2026-1", "CVE-2026-2"]);
  });
});
