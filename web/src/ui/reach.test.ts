import { describe, expect, it } from "vitest";
import { nothingToReview } from "./reach";

// The review sheet is skipped only when it is known to have nothing to ask.
// The distinction being tested is between "no other versions" and "not read
// yet", which look identical from the offered list alone.
describe("whether the review has anything to ask", () => {
  it("skips where the reach was read and named no other version", () => {
    expect(nothingToReview({ isSuccess: true }, [])).toBe(true);
  });

  it("asks where the reach named another version", () => {
    expect(nothingToReview({ isSuccess: true }, [{ key: "this build @ 1.2.3" }])).toBe(false);
  });

  it("asks while the reach is still being read", () => {
    // The empty list here is what has not arrived, not what is not there.
    expect(nothingToReview({ isSuccess: false }, [])).toBe(false);
  });

  it("asks where the reach could not be read at all", () => {
    // A failure and a request still in flight are the same thing here: the
    // answer is not known, and submitting past a question is not the same as
    // there being no question.
    expect(nothingToReview({ isSuccess: false }, [{ key: "unread" }])).toBe(false);
  });
});
