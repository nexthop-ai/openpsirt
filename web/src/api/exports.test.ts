// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { exportAt } from "./exports";

describe("a report file's address", () => {
  it("carries the format as an extension and the question as it was asked", () => {
    expect(exportAt("/v1/trend", "csv", new URLSearchParams({ weeks: "12" }))).toBe(
      "/v1/trend.csv?weeks=12",
    );
  });

  it("asks nothing where nothing was asked", () => {
    expect(exportAt("/v1/deferrals/repeated", "json", "")).toBe("/v1/deferrals/repeated.json");
    expect(exportAt("/v1/deferrals/repeated", "json")).toBe("/v1/deferrals/repeated.json");
  });
});
