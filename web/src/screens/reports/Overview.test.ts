// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { UNNARROWED } from "../../app/scope";
import { byProduct, openFor } from "./Overview";

// The parameters an address carries, one list per name.
function query(path: string): Record<string, string[]> {
  const asked = new URLSearchParams(path.includes("?") ? path.slice(path.indexOf("?")) : "");
  const out: Record<string, string[]> = {};
  for (const [name, value] of asked) (out[name] ??= []).push(value);
  return out;
}

const branch = { product: "sonic", stream: "master" };

// The list's own defaults lifted, because no bucket applies them.
const everything = query(`?${UNNARROWED}`);

describe("an aging bucket's link", () => {
  it("asks for the youngest bucket by its end alone", () => {
    expect(query(openFor(branch, 0, 7))).toEqual({
      stream: ["master"],
      open_under: ["7"],
      below: ["yes"],
      ...everything,
    });
  });

  it("asks for a bucket in the middle by both ends", () => {
    expect(query(openFor(branch, 7, 28))).toEqual({
      stream: ["master"],
      open_for: ["7"],
      open_under: ["28"],
      below: ["yes"],
      ...everything,
    });
  });

  it("asks for the oldest bucket by its start alone", () => {
    expect(query(openFor(branch, 90, 0))).toEqual({
      stream: ["master"],
      open_for: ["90"],
      below: ["yes"],
      ...everything,
    });
  });

  it("keeps a further filter as its own parameter on a partial scope", () => {
    expect(query(openFor(branch, 28, 90, { state: "undecided" }))).toEqual({
      stream: ["master"],
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
