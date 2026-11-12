// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - node's types are not loaded for the interface's tests
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
// @ts-expect-error - node's types are not loaded for the interface's tests
import { tmpdir } from "node:os";
// @ts-expect-error - node's types are not loaded for the interface's tests
import path from "node:path";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { isMain } from "./parsed.mjs";

// A check run through a symbolic link is still the program, so it runs rather
// than exiting clean having checked nothing.
describe("whether a check is the program node was started with", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "is-main-"));
  const real = path.join(dir, "check.mjs");
  writeFileSync(real, "");
  const linked = path.join(dir, "linked");
  symlinkSync(dir, linked);

  it("is, started through a symbolic link to its directory", () => {
    expect(isMain({ filename: real }, path.join(linked, "check.mjs"))).toBe(true);
  });

  it("is not, where another file was started", () => {
    const other = path.join(dir, "other.mjs");
    writeFileSync(other, "");
    expect(isMain({ filename: real }, other)).toBe(false);
  });

  it("is not, where nothing was started", () => {
    expect(isMain({ filename: real }, undefined)).toBe(false);
  });
});
