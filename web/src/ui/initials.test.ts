import { describe, expect, it } from "vitest";
import { initials } from "./initials";

// There were three of these and they had drifted: two split an address on the
// `@` and one did not, so one person had two avatars on one screen — which
// reads as two people rather than as a rendering difference.
describe("the letters standing for somebody", () => {
  it("takes the local part of an address rather than the domain", () => {
    expect(initials("alice@example.com")).toBe("AE");
  });

  it("drops the provider an identity is written with", () => {
    // `provider:username`. Taking the first letters of "proxy" says nothing
    // about anybody.
    expect(initials("proxy:dev")).toBe("DE");
  });

  it("uses two names where there are two", () => {
    expect(initials("ana.morales")).toBe("AM");
    expect(initials("Ben Okoro")).toBe("BO");
  });

  it("answers something for a name it cannot split", () => {
    expect(initials("dev")).toBe("DE");
    expect(initials("")).toBe("?");
  });
});
