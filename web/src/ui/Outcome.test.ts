import { describe, expect, it } from "vitest";
import { called, labeled } from "./Outcome";

// The word comes from the server. Looked up by indexing an object literal, a
// word naming a member of the prototype — `constructor`, `toString` — came
// back as a function rather than as nothing, and the optional chain that
// guards the lookup does not guard the field read after it. The render then
// threw on a value that arrived over the network.

describe("an outcome the interface does not know", () => {
  it("is shown as it arrived rather than crashing the render", () => {
    for (const word of ["constructor", "toString", "valueOf", "__proto__", "hasOwnProperty"]) {
      expect(() => labeled(word)).not.toThrow();
      expect(() => called(word)).not.toThrow();
      expect(labeled(word)).toBe(word);
      expect(called(word)).toBe(word);
    }
  });

  it("is still shown as it arrived for a word nobody has ever used", () => {
    expect(labeled("newly-invented")).toBe("newly-invented");
  });
});

describe("an outcome the interface knows", () => {
  it("is shown as the word a person reads", () => {
    expect(labeled("not-applicable")).not.toBe("not-applicable");
    expect(called("not-applicable")).toBe(labeled("not-applicable").toLowerCase());
  });
});
