// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { initials } from "./initials";

// One person has one avatar on every screen, and two people at one domain have
// two.
describe("the letters standing for somebody", () => {
  it("takes the local part of an address rather than the domain", () => {
    expect(initials("alice@example.com")).toBe("AL");
    expect(initials("adam@example.com")).toBe("AD");
    expect(initials("ana.morales@example.com")).toBe("AM");
  });

  it("reads an identity as the username it is", () => {
    // One provider is configured at a time, so an identity is the username
    // with nothing in front of it. Written `provider:username`, the prefix
    // would have to be stripped here.
    expect(initials("dev")).toBe("DE");
  });

  it("uses two names where there are two", () => {
    expect(initials("ana.morales")).toBe("AM");
    expect(initials("Ben Okoro")).toBe("BO");
  });

  it("answers something for a name it cannot split", () => {
    expect(initials("")).toBe("?");
    expect(initials("@example.com")).toBe("?");
  });
});
