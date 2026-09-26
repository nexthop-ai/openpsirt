// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { reaffirmedNotice } from "./ReaffirmMany";

describe("reaffirmedNotice", () => {
  it("says nothing waits where every claim stood", () => {
    expect(reaffirmedNotice({ claims: 3, waiting: 0 })).toBe("Reaffirmed 3 claims.");
  });
  it("counts the claims waiting for a second person", () => {
    expect(reaffirmedNotice({ claims: 1, waiting: 1 })).toBe(
      "Reaffirmed 1 claim; 1 waits for a second person.",
    );
  });
});
