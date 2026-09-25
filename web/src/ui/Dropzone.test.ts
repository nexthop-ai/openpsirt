// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { picked, sizeSaid } from "./Dropzone";

const file = (name: string, size: number) => new File([new Uint8Array(size)], name);

describe("picked", () => {
  it("adds to what is there for a zone taking several", () => {
    const a = file("a.txt", 3);
    const b = file("b.txt", 4);
    expect(picked([a], [b], true).map((f) => f.name)).toEqual(["a.txt", "b.txt"]);
  });

  it("lists a file with the same name and size once", () => {
    const a = file("a.txt", 3);
    expect(picked([a], [file("a.txt", 3)], true)).toHaveLength(1);
    expect(picked([a], [file("a.txt", 5)], true)).toHaveLength(2);
  });

  it("replaces what is there for a zone taking one", () => {
    const a = file("a.txt", 3);
    const b = file("b.txt", 4);
    expect(picked([a], [b, file("c.txt", 1)], false)).toEqual([b]);
  });
});

describe("sizeSaid", () => {
  it("says kilobytes, at least one, and megabytes past one", () => {
    expect(sizeSaid(10)).toBe("1 KB");
    expect(sizeSaid(2048)).toBe("2 KB");
    expect(sizeSaid(3 * 1048576)).toBe("3.0 MB");
  });
});
