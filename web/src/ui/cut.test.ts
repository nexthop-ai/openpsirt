// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { cut } from "./cut";

describe("text shortened to fit", () => {
  it("leaves text that fits as it is", () => {
    expect(cut("A short description.", 420)).toBe("A short description.");
  });

  it("marks where longer text was cut", () => {
    expect(cut("one two three", 7)).toBe("one two…");
  });

  it("never cuts inside a character", () => {
    // Stored as two units each, so a cut by units falls between the halves.
    const text = "ab😀😀😀";
    expect(cut(text, 3)).toBe("ab😀…");
    expect(cut(text, 3).includes("\ud83d…")).toBe(false);
  });

  it("never cuts inside what a reader sees as one character", () => {
    // A flag is two code points, and an accent written after its letter is a
    // second one: a cut by code points keeps half of each.
    expect(cut("ab🇫🇷🇫🇷", 3)).toBe("ab🇫🇷…");
    expect(cut("café au lait", 4)).toBe("café…");
  });
});
