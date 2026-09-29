// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  agreeing,
  madeOnLabel,
  markable,
  missing,
  nameable,
  releaseStatus,
  standing,
  statusLabel,
} from "./advisory";

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
    // The pairs, not merely that a word maps to something: swapping two
    // entries of the table leaves an agreed advisory labelled Interim, with
    // the hover sentence saying nobody agrees to it.
    for (const [word, label] of [
      ["draft", "Draft"],
      ["final", "Final"],
      ["interim", "Interim"],
    ]) {
      expect(statusLabel(word)).toBe(label);
      expect(standing(word)?.means).toBeTruthy();
    }
  });

  it("do not tell a reader that an interim document has changed since it went out", () => {
    // A withdrawn agreement reaches interim with nothing a reader acts on
    // having moved, so a sentence about a change is one that is often false.
    expect(standing("interim")?.means).not.toMatch(/chang/i);
  });
});

describe("who agrees to what an advisory says", () => {
  it("is nobody, where nobody does", () => {
    expect(agreeing(0)).toBe("Nobody agrees");
  });

  it("is one person, in the singular", () => {
    expect(agreeing(1)).toBe("One person agrees");
  });

  it("is a count, in the plural", () => {
    expect(agreeing(3)).toBe("3 people agree");
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

  it("offer a flaw that arrives twice once", () => {
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
      { vulnerability: "CVE-2026-3", summary: "", fixed: false },
    ]);
  });

  it("call a flaw fixed only where none of it is open", () => {
    const offered = nameable(
      [
        { vulnerability: "CVE-2026-4", open: 0 },
        { vulnerability: "CVE-2026-5", open: 2 },
      ],
      [],
      "switch",
    );
    expect(offered.map((one) => one.fixed)).toEqual([true, false]);
  });

  it("are not narrowed by a covered entry carrying no identifier", () => {
    expect(
      nameable(rows, [{ product: "switch" }], "switch").map((one) => one.vulnerability),
    ).toEqual(["CVE-2026-1", "CVE-2026-2"]);
  });
});

describe("what a document states about a release", () => {
  it("is each of the three statuses in words", () => {
    expect(releaseStatus("known_affected").label).toBe("Affected");
    expect(releaseStatus("known_not_affected").label).toBe("Not affected");
    expect(releaseStatus("fixed").label).toBe("Fixed");
  });

  it("is a word the interface does not know, shown as it arrived", () => {
    expect(releaseStatus("under_investigation").label).toBe("under_investigation");
    expect(releaseStatus("constructor").label).toBe("constructor");
  });
});

describe("marking a release affected", () => {
  const covered = { decision: 1, outcome: "not-applicable", made_on: [] };

  it("is offered where a decision moves the release off affected", () => {
    expect(markable({ covered, decided: "known_not_affected" })).toBe(true);
    expect(markable({ covered, decided: "fixed" })).toBe(true);
  });

  it("is not offered where the decisions leave it affected, or where none covers it", () => {
    expect(markable({ covered, decided: "known_affected" })).toBe(false);
    expect(markable({ decided: "fixed" })).toBe(false);
    expect(markable({ covered: null, decided: "fixed" })).toBe(false);
  });
});

describe("the builds a decision was made on", () => {
  it("are named the way a release is", () => {
    expect(
      madeOnLabel([
        { stream: "master", variant: "broadcom" },
        { stream: "master", variant: "mellanox" },
      ]),
    ).toBe("master (broadcom), master (mellanox)");
  });

  it("are said to be not recorded where there are none, rather than left blank", () => {
    expect(madeOnLabel([])).toBe("not recorded");
    expect(madeOnLabel(null)).toBe("not recorded");
    expect(madeOnLabel(undefined)).toBe("not recorded");
  });
});
