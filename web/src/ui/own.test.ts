// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { own } from "./own";

describe("a table's entry for a word", () => {
  const table = { waiting: "waiting for a second person" };

  it("is the entry where the table holds the word", () => {
    expect(own(table, "waiting")).toBe("waiting for a second person");
  });

  it("is nothing where the word names a member every object inherits", () => {
    expect(own(table, "constructor")).toBeUndefined();
    expect(own(table, "toString")).toBeUndefined();
  });

  it("is nothing where there is no word", () => {
    expect(own(table, undefined)).toBeUndefined();
    expect(own(table, null)).toBeUndefined();
  });
});
