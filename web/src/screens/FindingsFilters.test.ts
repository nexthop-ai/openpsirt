// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { activeFilters, without, withoutAny } from "./FindingsFilters";

// The chips above the findings list: what narrows it, read from the address,
// and what removing each one leaves.
const address = (query: string) => new URLSearchParams(query);
const chips = (query: string | URLSearchParams) =>
  activeFilters(typeof query === "string" ? address(query) : query).map(
    (each) => `${each.label}: ${each.value}`,
  );

describe("the chips an address draws", () => {
  it("draws none for an address that narrows nothing", () => {
    expect(chips("")).toEqual([]);
  });

  it("draws none for a parameter that is present and empty", () => {
    // An empty pick labels as "Any", which is a label and not a narrowing.
    expect(chips("origin=&running=&fix_state=&floor=")).toEqual([]);
  });

  it("draws none for the least severity, which excludes nothing", () => {
    expect(chips("floor=low")).toEqual([]);
    expect(chips("floor=critical")).toEqual(["Severity: Critical only"]);
  });

  it("draws one chip per value of a filter asked for twice", () => {
    expect(chips("state=undecided&state=waiting")).toEqual([
      "Decision state: Undecided",
      "Decision state: Pending approval",
    ]);
  });

  it("draws a chip for known-exploited and for a fix version known", () => {
    expect(chips("exploited=1")).toEqual(["Known exploited: only"]);
    expect(chips("fixable=1")).toEqual(["Fix version known: only"]);
  });

  it("draws a chip for one of two releases, and none for both", () => {
    expect(chips("on=tag")).toEqual(["Release: Tags"]);
    expect(chips("on=branch&on=tag")).toEqual([]);
  });
});

describe("removing a chip", () => {
  const removed = (query: string, index = 0) => {
    const params = address(query);
    const chip = activeFilters(params)[index];
    if (!chip) throw new Error(`no chip ${index} for ${query}`);
    return without(params, chip);
  };

  it("removes one value of a filter asked for twice and leaves the other", () => {
    const left = removed("state=undecided&state=waiting");
    expect(left.getAll("state")).toEqual(["waiting"]);
    expect(chips(left)).toEqual(["Decision state: Pending approval"]);
  });

  it("removes known-exploited and leaves a fix version known", () => {
    const left = removed("exploited=1&fixable=1");
    expect(left.has("exploited")).toBe(false);
    expect(left.get("fixable")).toBe("1");
  });

  it("widens a one-of-two filter to both rather than dropping it", () => {
    // Dropping the parameter asks for the default back, which is itself one of
    // the two.
    const left = removed("on=tag");
    expect(left.getAll("on")).toEqual(["branch", "tag"]);
    expect(chips(left)).toEqual([]);
  });

  it("widens a planned-upgrade filter to either", () => {
    const left = removed("planned=unplanned");
    expect(left.getAll("planned")).toEqual(["either"]);
    expect(chips(left)).toEqual([]);
  });

  it("leaves what is not a filter in the address", () => {
    const left = removed("q=openssl&view=issues&offset=50");
    expect(left.has("q")).toBe(false);
    expect(left.get("view")).toBe("issues");
    expect(left.get("offset")).toBe("50");
  });
});

describe("clearing every chip", () => {
  it("leaves nothing narrowing, and keeps what is not a filter", () => {
    const left = withoutAny(
      address(
        "q=ssl&floor=high&state=undecided&state=waiting&exploited=1&on=tag&support=past-eol" +
          "&planned=planned&hide=zlib&origin=manual&view=issues",
      ),
    );
    expect(chips(left)).toEqual([]);
    expect(left.get("view")).toBe("issues");
  });

  it("changes nothing where nothing narrows", () => {
    expect(withoutAny(address("view=issues")).toString()).toBe("view=issues");
  });
});
