// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { scanState } from "./fixes";

describe("scanState", () => {
  it("says a release nobody scanned is not scanned", () => {
    expect(scanState({ scanned: false, open: false })).toBe("not scanned");
  });
  it("says an issue is open where a scan holds it open", () => {
    expect(scanState({ scanned: true, open: true })).toBe("open in its latest scans");
  });
  it("says an issue is not found where the scans hold it nowhere", () => {
    expect(scanState({ scanned: true, open: false })).toBe("not found in its latest scans");
  });
});
