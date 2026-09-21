import { describe, expect, it } from "vitest";
import { ranked, rankedLabel, rankedWhy, upgradeCount } from "./ranked";

// An unranked list is the ordinary state for most of what a scan reports:
// an ordering exists per ecosystem, and the ones without one are the long
// tail. So the screen has to say which of the two counts it is drawing, and
// the same two counts with no word on them is the failure being pinned.

describe("what a list of candidates says about itself", () => {
  it("says why a list is not ranked", () => {
    expect(rankedWhy(false)).toMatch(/could not be put in order/);
    expect(rankedLabel(false)).toBe("Not ranked");
  });

  it("says something different where it is ranked", () => {
    expect(rankedWhy(true)).not.toBe(rankedWhy(false));
    expect(rankedLabel(true)).not.toBe(rankedLabel(false));
  });

  it("names which count it is drawing, in both states", () => {
    expect(upgradeCount({ ordered: true, reached: 7, fixed_here: 2 })).toBe("closes 7");
    expect(upgradeCount({ ordered: false, reached: 7, fixed_here: 2 })).toBe("fixed 2");
  });

  it("counts nothing rather than crashing where the number did not arrive", () => {
    expect(upgradeCount({ ordered: true })).toBe("closes 0");
    expect(upgradeCount({ ordered: false })).toBe("fixed 0");
  });
});

describe("whether a set of candidates is ranked", () => {
  it("is ranked where the candidates say so", () => {
    expect(ranked([{ ordered: true }, { ordered: true }])).toBe(true);
  });

  it("is not ranked where they say so", () => {
    expect(ranked([{ ordered: false }])).toBe(false);
  });

  // The distinction that matters. An empty list is a read that failed or has
  // not come back, and drawing that as a ranking puts "closes 7" under a
  // heading claiming the first release closes the most, off nothing.
  it("is not ranked where nothing has been read", () => {
    expect(ranked([])).toBe(false);
    expect(ranked([{}])).toBe(false);
  });
});
