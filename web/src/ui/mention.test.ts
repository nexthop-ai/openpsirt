// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { mentionOf } from "./mention";

describe("mentionOf", () => {
  it("writes a plain identity after a bare @", () => {
    expect(mentionOf("ana")).toBe("@ana");
    expect(mentionOf("proxy:dev")).toBe("@proxy:dev");
    expect(mentionOf("ana@example.com")).toBe("@ana@example.com");
  });

  it("delimits an identity the plain form would cut short", () => {
    expect(mentionOf("ana+psirt@example.com")).toBe("@\\<ana+psirt@example.com>");
    expect(mentionOf("auth0|abc123")).toBe("@\\<auth0|abc123>");
    expect(mentionOf("Ana Smith")).toBe("@\\<Ana Smith>");
    expect(mentionOf("josé")).toBe("@\\<josé>");
    expect(mentionOf("ana.")).toBe("@\\<ana.>");
  });

  it("escapes what markdown would read inside the brackets", () => {
    expect(mentionOf("a>b")).toBe("@\\<a\\>b>");
    expect(mentionOf("_svc_")).toBe("@\\<\\_svc\\_>");
    expect(mentionOf("DOMAIN\\ana")).toBe("@\\<DOMAIN\\\\ana>");
  });
});
