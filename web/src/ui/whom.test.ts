// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { matching, offeredAs, whoIs } from "./whom";

const people = [
  { identity: "abc123", name: "Ana Ruiz" },
  { identity: "def456", name: "Ana Ruiz" },
  { identity: "ben", name: "ben" },
];

describe("offering a person in a picker", () => {
  it("carries the identity beside the name where they differ", () => {
    // Two colleagues can share a display name, and a picker offering only
    // that would resolve to whichever of them the list held first.
    expect(offeredAs(people[0]!)).toBe("Ana Ruiz (abc123)");
    expect(offeredAs(people[2]!)).toBe("ben");
  });

  it("resolves only what somebody was actually offered", () => {
    // The reason the button stays disabled. Neither picker can bring anybody
    // into the deployment, so a name matching nobody is refused by the server —
    // and being refused after typing is a worse way to learn that.
    expect(whoIs("Ana Ruiz (def456)", people)).toBe("def456");
    expect(whoIs("ben", people)).toBe("ben");
    // The identity alone, for somebody who knows it.
    expect(whoIs("abc123", people)).toBe("abc123");
    // A display name two people share resolves to neither: it is not an
    // answer to "which of them".
    expect(whoIs("Ana Ruiz", people)).toBe("");
    expect(whoIs("somebody else", people)).toBe("");
    expect(whoIs("  ", people)).toBe("");
  });

  it("narrows on either half, ignoring capitals", () => {
    // The same rule the server matches on, so a list narrowed here and one
    // narrowed there hold the same people.
    expect(matching("ana", people).map((each) => each.identity)).toEqual(["abc123", "def456"]);
    expect(matching("DEF", people).map((each) => each.identity)).toEqual(["def456"]);
    expect(matching("", people)).toHaveLength(3);
  });
});
