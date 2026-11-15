// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { answer, serve } from "./mount";

// The two tests run in order: the first installs a fake server, the second
// reads the client it left behind.
describe("a fake server", () => {
  it("is installed on the generated client by the test that serves", () => {
    serve(() => ({ data: [] }));
    answer("POST", () => ({ status: 204 }));
    expect(vi.isMockFunction(api.GET)).toBe(true);
    expect(vi.isMockFunction(api.POST)).toBe(true);
  });

  it("answers nothing in the test after it", () => {
    expect(vi.isMockFunction(api.GET)).toBe(false);
    expect(vi.isMockFunction(api.POST)).toBe(false);
  });
});
