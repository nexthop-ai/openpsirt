import { describe, expect, it } from "vitest";
import { on, since } from "./when";

// Two forms and no others. There were four in use at once, two of them
// showing the stored string with its time and offset — the tool displaying its
// storage rather than answering the question.
describe("how a moment is written", () => {
  const now = new Date("2026-09-07T12:00:00Z");

  it("writes the calendar day, as stored", () => {
    expect(on("2026-09-04T08:13:44.123456Z")).toBe("2026-09-04");
  });

  it("says nothing about a moment that is not there", () => {
    // Absent is a different thing from the start of the epoch, and every
    // caller has its own words for it.
    expect(on(null)).toBe("");
    expect(on(undefined)).toBe("");
    expect(since(null, now)).toBe("");
  });

  it("says nothing about a moment it cannot read", () => {
    expect(since("last week", now)).toBe("");
  });

  it("answers how long ago in the coarsest unit that still says something", () => {
    expect(since("2026-09-07T11:59:30Z", now)).toBe("just now");
    expect(since("2026-09-07T11:00:00Z", now)).toBe("1 hour ago");
    expect(since("2026-09-04T12:00:00Z", now)).toBe("3 days ago");
    expect(since("2026-08-07T12:00:00Z", now)).toBe("1 month ago");
  });

  it("reads the same scale the other way for a moment still ahead", () => {
    // A deadline, an embargo, an end of life: the same question about the
    // other side of now.
    expect(since("2026-09-10T12:00:00Z", now)).toBe("in 3 days");
    expect(since("2026-09-07T12:00:30Z", now)).toBe("in a moment");
  });
});
