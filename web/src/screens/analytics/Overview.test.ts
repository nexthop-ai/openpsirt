// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { BANDS } from "../../ui/severities";
import { UNNARROWED } from "../../app/scope";
import { fixTimes, openFor, undatedCount, undatedNote } from "./Overview";
import { byProduct } from "./catalog";

// The parameters an address carries, one list per name.
function query(path: string): Record<string, string[]> {
  const asked = new URLSearchParams(path.includes("?") ? path.slice(path.indexOf("?")) : "");
  const out: Record<string, string[]> = {};
  for (const [name, value] of asked) (out[name] ??= []).push(value);
  return out;
}

const branch = { product: "sonic", branch_or_tag: "master" };

// The list's own defaults lifted, because no bucket applies them.
const everything = query(`?${UNNARROWED}`);

describe("an aging bucket's link", () => {
  it("asks for the youngest bucket by its end alone", () => {
    expect(query(openFor(branch, 0, 7))).toEqual({
      branch_or_tag: ["master"],
      open_under: ["7"],
      below: ["yes"],
      ...everything,
    });
  });

  it("asks for a bucket in the middle by both ends", () => {
    expect(query(openFor(branch, 7, 28))).toEqual({
      branch_or_tag: ["master"],
      open_for: ["7"],
      open_under: ["28"],
      below: ["yes"],
      ...everything,
    });
  });

  it("asks for the oldest bucket by its start alone", () => {
    expect(query(openFor(branch, 90, 0))).toEqual({
      branch_or_tag: ["master"],
      open_for: ["90"],
      below: ["yes"],
      ...everything,
    });
  });

  it("keeps a further filter as its own parameter on a partial scope", () => {
    expect(query(openFor(branch, 28, 90, { state: "undecided" }))).toEqual({
      branch_or_tag: ["master"],
      state: ["undecided"],
      open_for: ["28"],
      open_under: ["90"],
      below: ["yes"],
      ...everything,
    });
  });
});

describe("a section counted by product alone", () => {
  it("names the product it was counted for, and no branch", () => {
    expect(byProduct("sonic")).toBe("sonic, every branch and variant");
  });

  it("says every product where none is picked", () => {
    expect(byProduct(undefined)).toBe("Every product");
  });
});

describe("the time to fix rows", () => {
  it("puts both figures side by side, worst first", () => {
    expect(
      fixTimes({
        time_to_fix: { low: 240, critical: 48 },
        time_to_fix_from_publication: { low: 720, critical: 96 },
      }),
    ).toEqual(
      BANDS.filter((band) => band === "critical" || band === "low").map((band) =>
        band === "critical"
          ? { band, seen: 48, published: 96, undated: 0 }
          : { band, seen: 240, published: 720, undated: 0 },
      ),
    );
  });

  it("leaves the publication figure absent where no fix has a date, and counts them", () => {
    expect(fixTimes({ time_to_fix: { high: 120 }, time_to_fix_undated: { high: 3 } })).toEqual([
      { band: "high", seen: 120, published: undefined, undated: 3 },
    ]);
  });

  it("is empty where nothing was fixed", () => {
    expect(fixTimes(undefined)).toEqual([]);
  });
});

describe("the undated hover", () => {
  it("counts the fixes left out", () => {
    expect(undatedNote(2)).toBe("2 fixes have no publication date and aren't counted here");
    expect(undatedNote(1)).toBe("1 fix has no publication date and isn't counted here");
  });

  it("says nothing where none is left out", () => {
    expect(undatedNote(0)).toBeUndefined();
  });
});

describe("the undated count on paper", () => {
  it("names how many fixes the figure leaves out", () => {
    expect(undatedCount(3)).toBe("(3 undated)");
  });
});
