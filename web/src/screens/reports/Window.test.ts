import { describe, expect, it } from "vitest";
import { coveringWords, daysAsked, wordsFor } from "./Window";

const asked = (query: string) => new URLSearchParams(query);

describe("the window a sheet was asked for", () => {
  it("takes what the address says", () => {
    expect(daysAsked(asked("days=7"), 30)).toBe(7);
    expect(daysAsked(asked("days=3650"), 30)).toBe(3650);
  });

  it("falls back where the address says nothing", () => {
    expect(daysAsked(asked(""), 30)).toBe(30);
  });

  it("refuses what is not a number", () => {
    // This is the one that matters: the value reaches date arithmetic on the
    // render path, and `new Date(NaN).toISOString()` throws rather than
    // returning a wrong date — which takes the whole sheet down.
    expect(daysAsked(asked("days=lastweek"), 30)).toBe(30);
    expect(daysAsked(asked("days="), 30)).toBe(30);
    expect(daysAsked(asked("days=Infinity"), 30)).toBe(30);
    expect(daysAsked(asked("days=NaN"), 30)).toBe(30);
  });

  it("refuses a window no sheet can answer for", () => {
    expect(daysAsked(asked("days=0"), 30)).toBe(30);
    expect(daysAsked(asked("days=-7"), 30)).toBe(30);
    expect(daysAsked(asked("days=99999"), 30)).toBe(30);
  });

  it("takes whole days from a fractional one", () => {
    expect(daysAsked(asked("days=7.9"), 30)).toBe(7);
  });
});

describe("what a window is called", () => {
  it("names the longest one for what it is", () => {
    expect(wordsFor(3650)).toBe("everything");
    expect(coveringWords(3650)).toBe("everything");
  });

  it("names a year as a year on every sheet", () => {
    expect(wordsFor(365)).toBe("a year");
    expect(coveringWords(365)).toBe("the last year");
  });

  it("counts the days otherwise", () => {
    expect(wordsFor(7)).toBe("7 days");
    expect(coveringWords(90)).toBe("the last 90 days");
  });
});
