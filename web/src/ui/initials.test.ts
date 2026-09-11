import { describe, expect, it } from "vitest";
import { initials } from "./initials";

// There were three of these and they had drifted: two split an address on the
// `@` and one did not, so one person had two avatars on one screen — which
// reads as two people rather than as a rendering difference.
describe("the letters standing for somebody", () => {
  it("takes the local part of an address rather than the domain", () => {
    expect(initials("alice@example.com")).toBe("AE");
  });

  it("reads an identity as the username it is", () => {
    // Identities were written `provider:username` and the prefix had to be
    // stripped here. One provider is configured at a time now, so an identity
    // is the username and there is nothing in front of it.
    expect(initials("dev")).toBe("DE");
    expect(initials("ashwin@example.com")).toBe("AE");
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
