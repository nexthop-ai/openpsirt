// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { checkedNothing as tokens } from "./tokens.mjs";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { checkedNothing as ladder } from "./one-ladder.mjs";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { checkedNothing as licenses } from "./licenses.mjs";

// A gate that iterates a collection fails where the collection is empty. Each
// program's only consumer is an exit code, and an exit code cannot tell a
// check that found nothing from one that looked at nothing.

describe("the token gate over nothing", () => {
  it("refuses a walk that found no file", () => {
    expect(tokens({ files: 0, defined: 0, named: 0 })).toContain("checked nothing");
  });

  it("refuses files that hold no definition or no reference", () => {
    expect(tokens({ files: 12, defined: 0, named: 0 })).toContain("checked nothing");
    expect(tokens({ files: 12, defined: 5, named: 0 })).toContain("checked nothing");
    expect(tokens({ files: 12, defined: 0, named: 5 })).toContain("checked nothing");
  });

  it("says nothing where it examined something", () => {
    expect(tokens({ files: 12, defined: 5, named: 5 })).toBe("");
  });
});

describe("the ladder gate over nothing", () => {
  it("refuses a walk that read no file", () => {
    expect(ladder(0)).toContain("checked nothing");
  });

  it("says nothing where it read one", () => {
    expect(ladder(1)).toBe("");
  });
});

describe("the license gate over nothing", () => {
  it("refuses a lockfile with no shipped dependency", () => {
    expect(licenses(0)).toContain("checked nothing");
  });

  it("says nothing where it checked one", () => {
    expect(licenses(1)).toBe("");
  });
});
