// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { asWeakness } from "./cwe";

describe("a typed weakness", () => {
  it("is taken in the shape the server records", () => {
    expect(asWeakness(" cwe-125 ")).toBe("CWE-125");
  });
  it("reads a bare number as that CWE", () => {
    expect(asWeakness("79")).toBe("CWE-79");
  });
  it("refuses anything the server would refuse", () => {
    // The whole record is refused over one, so it is caught where it is typed.
    for (const typed of ["CWE-0", "CWE-1234567", "NVD-CWE-Other", "buffer overflow", ""]) {
      expect(asWeakness(typed)).toBeNull();
    }
  });
});
