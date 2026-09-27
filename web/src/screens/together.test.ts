// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { skippedNotice } from "./Together";

describe("skippedNotice", () => {
  it("says one place in the singular", () => {
    expect(skippedNotice(1)).toBe("1 place skipped: a decision already stands there.");
  });
  it("counts several", () => {
    expect(skippedNotice(1200)).toBe("1,200 places skipped: a decision already stands at each.");
  });
});
