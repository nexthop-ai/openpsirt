// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { at, lasted, on, since, typedMoment, typedNow } from "./when";

// Two forms and no others. A stored string shown with its time and offset is
// the tool displaying its storage rather than answering the question.
describe("how a moment is written", () => {
  const now = new Date("2026-09-07T12:00:00Z");

  it("writes the calendar day, as stored", () => {
    expect(on("2026-09-04T08:13:44.123456Z")).toBe("2026-09-04");
  });

  it("writes a moment to the minute in UTC, whatever offset it was stored with", () => {
    // A window of hours ends on a different day depending on the hour it
    // opened, so the day alone does not answer when one runs out.
    expect(at("2026-09-04T23:13:44Z")).toBe("2026-09-04 23:13 UTC");
    expect(at("2026-09-05T01:13:44+02:00")).toBe("2026-09-04 23:13 UTC");
    expect(at("libnl-3-200")).toBe("");
    expect(at(null)).toBe("");
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
    // The absolute form asks the same question: a field that is not a moment
    // would otherwise be drawn as its own first ten characters, which reads
    // like a date and is not one.
    expect(on("last week")).toBe("");
    expect(on("libnl-3-200")).toBe("");
    expect(on("")).toBe("");
    // A bare number parses as a year in this language, so it has to be turned
    // away by shape rather than by whether a date can be made of it.
    expect(on("42")).toBe("");
  });

  it("takes a day with no time on it", () => {
    // Deadlines and end-of-life dates are stored as the day alone.
    expect(on("2026-09-04")).toBe("2026-09-04");
  });

  it("turns away a day that is shaped right and is not one", () => {
    expect(on("2026-13-45T00:00:00Z")).toBe("");
    // A parser rolls this into March rather than refusing it.
    expect(on("2026-02-30")).toBe("");
    expect(at("2026-02-30T00:00:00Z")).toBe("");
    expect(on("2028-02-29")).toBe("2028-02-29");
  });

  it("turns a non-moment away from the relative forms too", () => {
    const now = new Date("2026-09-07T12:00:00Z");
    // A bare number parses as a year.
    expect(since("42", now)).toBe("");
    expect(since("2026-02-30", now)).toBe("");
    expect(lasted("42", "2026-09-07T12:00:00Z")).toBe("");
    expect(lasted("2026-09-07T11:00:00Z", "43")).toBe("");
  });

  it("answers how long ago in the coarsest unit that still says something", () => {
    expect(since("2026-09-07T11:59:30Z", now)).toBe("just now");
    expect(since("2026-09-07T11:00:00Z", now)).toBe("1 hour ago");
    expect(since("2026-09-04T12:00:00Z", now)).toBe("3 days ago");
    // Week and year, the two rungs of the ladder nothing reached — so a
    // wrong divisor on either read as the unit above or below it with the
    // suite green.
    expect(since("2026-08-24T12:00:00Z", now)).toBe("2 weeks ago");
    expect(since("2026-08-07T12:00:00Z", now)).toBe("1 month ago");
    // A year is 365.25 days here, so two calendar years back is 1.998 of
    // them and reads as one. Which is the sort of thing a rung nothing
    // exercises gets wrong quietly.
    expect(since("2024-06-07T12:00:00Z", now)).toBe("2 years ago");
  });

  it("reads the same scale the other way for a moment still ahead", () => {
    // A deadline, an embargo, an end of life: the same question about the
    // other side of now.
    expect(since("2026-09-10T12:00:00Z", now)).toBe("in 3 days");
    expect(since("2026-09-07T12:00:30Z", now)).toBe("in a moment");
  });
});

describe("how long something took", () => {
  it("says seconds outright below a minute", () => {
    // A scan that took nine seconds and one that took fifty are different
    // things, and "0 minutes" says neither.
    expect(lasted("2026-03-01T00:00:00Z", "2026-03-01T00:00:09Z")).toBe("9 seconds");
    expect(lasted("2026-03-01T00:00:00Z", "2026-03-01T00:00:01Z")).toBe("1 second");
    expect(lasted("2026-03-01T00:00:00Z", "2026-03-01T00:00:50Z")).toBe("50 seconds");
  });

  it("uses the coarsest unit that still says something", () => {
    expect(lasted("2026-03-01T00:00:00Z", "2026-03-01T00:04:00Z")).toBe("4 minutes");
    expect(lasted("2026-03-01T00:00:00Z", "2026-03-01T03:30:00Z")).toBe("3 hours");
  });

  it("answers nothing where there is no pair, or the pair is impossible", () => {
    expect(lasted(null, "2026-03-01T00:00:00Z")).toBe("");
    expect(lasted("2026-03-01T00:00:00Z", undefined)).toBe("");
    expect(lasted("not a moment", "2026-03-01T00:00:00Z")).toBe("");
    // A run that finished before it started is a clock nobody should be told
    // a duration from.
    expect(lasted("2026-03-01T01:00:00Z", "2026-03-01T00:00:00Z")).toBe("");
  });
});

// A typed minute and the moment the record shows afterwards are the same
// minute, because both are UTC.
describe("how a typed minute is read", () => {
  // A zone seven hours behind UTC, so a minute read as local time lands on a
  // different minute from the one typed. Under UTC the two readings agree and
  // nothing here could fail.
  beforeAll(() => {
    vi.stubEnv("TZ", "America/Los_Angeles");
  });
  afterAll(() => {
    vi.unstubAllEnvs();
  });

  it("reads the minute typed as UTC, whatever zone the reader is in", () => {
    expect(new Date("2026-10-03T22:00").getTimezoneOffset()).not.toBe(0);
    expect(typedMoment("2026-10-03T22:00")).toBe("2026-10-03T22:00:00.000Z");
    expect(at(typedMoment("2026-10-03T22:00"))).toBe("2026-10-03 22:00 UTC");
    // A browser that offers seconds hands them over, and the minute is kept.
    expect(typedMoment("2026-10-03T22:00:30")).toBe("2026-10-03T22:00:00.000Z");
  });

  it("offers now as the minute it is in UTC", () => {
    expect(typedNow(new Date("2026-10-04T02:45:59Z"))).toBe("2026-10-04T02:45");
  });

  it("reads nothing from an input holding no minute", () => {
    expect(typedMoment("")).toBe("");
    expect(typedMoment("2026-10-03")).toBe("");
    expect(typedMoment("2026-13-40T99:99")).toBe("");
  });
});
