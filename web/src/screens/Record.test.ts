// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { unpicked } from "./Record";

const read = { isPending: false, isError: false };

describe("an empty list of builds to pick from", () => {
  it("asks for a product before anything else", () => {
    expect(unpicked("", { ...read, isError: true })).toBe("Pick a product first");
  });

  it("says a failed read failed rather than that nothing is declared", () => {
    expect(unpicked("sonic", { ...read, isError: true })).toBe("Could not be read");
  });

  it("says nothing is declared only once the read has answered", () => {
    expect(unpicked("sonic", { ...read, isPending: true })).toBe("Reading…");
    expect(unpicked("sonic", read)).toBe("Nothing is declared here yet");
  });
});
