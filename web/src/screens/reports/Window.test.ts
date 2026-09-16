import { describe, expect, it } from "vitest";
import {
  asked as asked2,
  coveringPeriod,
  coveringWords,
  daysAsked,
  periodAsked,
  wordsFor,
} from "./Window";

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

describe("the period a sheet was asked for", () => {
  it("takes two dates from the address", () => {
    expect(periodAsked(asked("from=2026-01-01&to=2026-04-01"))).toEqual({
      from: "2026-01-01",
      to: "2026-04-01",
    });
  });

  it("takes either side on its own", () => {
    // A start with no end runs to now, and an end with no start runs from the
    // beginning. Both are real questions and neither is half of a mistake.
    expect(periodAsked(asked("from=2026-01-01"))).toEqual({ from: "2026-01-01", to: "" });
    expect(periodAsked(asked("to=2026-04-01"))).toEqual({ from: "", to: "2026-04-01" });
  });

  it("refuses what is not a date", () => {
    // The same reason the window is checked: these reach date arithmetic on
    // the render path and go to the server, which refuses what it cannot read.
    expect(periodAsked(asked("from=last-quarter"))).toEqual({ from: "", to: "" });
    expect(periodAsked(asked("from=2026-13-45"))).toEqual({ from: "", to: "" });
    expect(periodAsked(asked("from=2026-01"))).toEqual({ from: "", to: "" });
  });

  it("refuses a period that ends before it starts", () => {
    // It holds nothing, and the server refuses it — so the sheet asks a
    // question that can be answered rather than drawing an error.
    expect(periodAsked(asked("from=2026-06-01&to=2026-01-01"))).toEqual({ from: "", to: "" });
  });

  it("sends a period or a window and never both", () => {
    // The two are ways of saying the same thing, and sending both is refused
    // by the server: a caller who sent both meant one of them.
    expect(asked2({ from: "2026-01-01", to: "2026-04-01" }, 30)).toEqual({
      from: "2026-01-01",
      to: "2026-04-01",
    });
    expect(asked2({ from: "", to: "" }, 30)).toEqual({ days: 30 });
    expect(asked2({ from: "2026-01-01", to: "" }, 30)).toEqual({ from: "2026-01-01" });
  });

  it("names the stretch it covers either way", () => {
    expect(coveringPeriod({ from: "", to: "" }, 30)).toBe("the last 30 days");
    expect(coveringPeriod({ from: "2026-01-01", to: "2026-04-01" }, 30)).toBe(
      "2026-01-01 to 2026-04-01",
    );
    expect(coveringPeriod({ from: "2026-01-01", to: "" }, 30)).toBe("2026-01-01 onwards");
    expect(coveringPeriod({ from: "", to: "2026-04-01" }, 30)).toBe("everything up to 2026-04-01");
  });
});
