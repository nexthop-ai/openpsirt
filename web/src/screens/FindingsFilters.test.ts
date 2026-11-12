// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { activeFilters, kindsOffered, unbumped, without, withoutAny } from "./FindingsFilters";
import { BUMP_FILTERS, bumpQuery } from "./FindingsViews";
import { listQuery } from "./list";

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

  it("takes a subtree's qualifiers with its root", () => {
    const left = removed("beneath=openssl&beneath_version=3.0.2&beneath_ecosystem=deb");
    expect(left.has("beneath")).toBe(false);
    expect(left.has("beneath_version")).toBe(false);
    expect(left.has("beneath_ecosystem")).toBe(false);
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

describe("the package kinds the filter offers", () => {
  it("are the kinds the server reports, in its order, with their counts", () => {
    expect(
      kindsOffered(
        [
          { kind: "deb", open: 4210 },
          { kind: "conan", open: 3 },
        ],
        [],
      ),
    ).toEqual([
      ["deb", "Debian (deb) · 4,210"],
      ["conan", "conan · 3"],
    ]);
  });

  it("keep a kind already chosen that the scope does not hold", () => {
    // Ticked on another scope and carried here by a link: offered so it can
    // be seen and unticked, and without a count, because there is nothing.
    expect(kindsOffered([{ kind: "deb", open: 1 }], ["deb", "apk"])).toEqual([
      ["deb", "Debian (deb) · 1"],
      ["apk", "Alpine (apk)"],
    ]);
  });

  it("draw a chip naming the kind, and removing it removes that kind alone", () => {
    const asked = address("ecosystem=cargo&ecosystem=swift");
    expect(chips(asked)).toEqual(["Package type: Rust (cargo)", "Package type: swift"]);
    const cargo = activeFilters(asked)[0]!;
    expect(without(asked, cargo).toString()).toBe("ecosystem=swift");
  });

  it("draw a chip naming a package identifier, and removing it removes it", () => {
    const asked = address("purl=pkg%3Acargo%2Fgimli&ecosystem=cargo");
    expect(chips(asked)).toEqual(["Package type: Rust (cargo)", "Package: pkg:cargo/gimli"]);
    const purl = activeFilters(asked)[1]!;
    expect(without(asked, purl).toString()).toBe("ecosystem=cargo");
  });
});

describe("the weakness chips", () => {
  it("name a weakness where its names have been read, and the catalog's name on hover", () => {
    const names = new Map([
      [
        "CWE-119",
        {
          id: "CWE-119",
          name: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
          short: "Buffer overflow",
        },
      ],
      ["CWE-1321", { id: "CWE-1321", name: "Prototype Pollution" }],
    ]);
    const drawn = activeFilters(
      address("weakness=CWE-119&weakness=CWE-1321&weakness=CWE-9"),
      names,
    );
    expect(drawn.map((each) => `${each.label}: ${each.value}`)).toEqual([
      "Weakness: CWE-119 Buffer overflow",
      "Weakness: CWE-1321 Prototype Pollution",
      "Weakness: CWE-9",
    ]);
    expect(drawn[0]?.title).toBe(names.get("CWE-119")?.name);
    expect(drawn[2]?.title).toBeUndefined();
  });

  it("show the number alone before the names are read", () => {
    expect(chips("weakness=CWE-79")).toEqual(["Weakness: CWE-79"]);
  });
});

// An address with every filter a chip names in force.
const EVERY = new URLSearchParams(
  [
    "q=ssl",
    "floor=high",
    "below=yes",
    "exploited=1",
    "fixable=1",
    "epss_at_least=0.5",
    "fix_state=fixed",
    "state=undecided",
    "outcome=not-affected",
    "sent_back=1",
    "planned=planned",
    "on=branch",
    "support=past-eol",
    "assigned=me",
    "reassessed=1",
    "origin=manual",
    "unconfirmed=1",
    "vex_publisher=acme",
    "vex_status=fixed",
    "build_says=affected",
    "component=curl",
    "ecosystem=deb",
    "purl=pkg:deb/debian/curl",
    "declared_as=library",
    "under=sonic-swss",
    "beneath=curl",
    "under_build=yes",
    "hide=zlib",
    "running=overdue",
    "open_for=30",
    "open_under=90",
    "opened_after=2026-01-01",
    "opened_before=2026-06-01",
    "open_on=2026-03-01",
    "opened_by_run=7",
    "decision=12",
    "proposed_after=2026-01-01",
    "closed_after=2026-01-01",
    "weakness=CWE-79",
    "label=mine",
    "differs=1",
    "variants=only",
  ].join("&"),
);

describe("a chip and the list it narrows", () => {
  it("draws none for a value the list does not send", () => {
    for (const address of [
      "open_for=0",
      "open_under=soon",
      "epss_at_least=1.5",
      "epss_at_least=0",
      "floor=bogus",
      "opened_after=2026-02-30",
      "open_on=yesterday",
      "state=bogus",
      "outcome=bogus",
      "fix_state=bogus",
      "vex_status=bogus",
      "build_says=bogus",
      "declared_as=bogus",
      "assigned=bogus",
      "origin=bogus",
      "planned=bogus",
      "decision=abc",
      "opened_by_run=-1",
      "running=never",
      "hide=%20",
      "on=branch&on=bogus&on=tag",
    ]) {
      expect(activeFilters(new URLSearchParams(address)), address).toEqual([]);
    }
  });

  it("narrows the request for every chip it draws", () => {
    const params = EVERY;
    const chips = activeFilters(params);
    expect(chips.length).toBeGreaterThan(0);
    const sent = JSON.stringify(listQuery(params));
    for (const chip of chips) {
      expect(JSON.stringify(listQuery(without(params, chip))), chip.key).not.toBe(sent);
    }
  });
});

describe("a chip and the by-upgrade list", () => {
  it("narrows the upgrades exactly where the view names the filter as applied", () => {
    const at = { product: "sonic", branch_or_tag: "master", variant: "broadcom" };
    const sent = (params: URLSearchParams) =>
      JSON.stringify(bumpQuery(at, listQuery(params), 50, 0));
    const chips = activeFilters(EVERY);
    expect(chips.length).toBeGreaterThan(0);
    for (const chip of chips) {
      expect(sent(without(EVERY, chip)) !== sent(EVERY), chip.key).toBe(chip.key in BUMP_FILTERS);
    }
  });
});

describe("a chip and the by-upgrade list", () => {
  it("names only filters in force over the selection as ones it cannot apply", () => {
    const params = new URLSearchParams("beneath=openssl&state=undecided&state=affected");
    const oneBuild = { product: "sonic", branch_or_tag: "master", variant: "broadcom" };
    const wholeProduct = { product: "sonic", branch_or_tag: "", variant: "" };
    expect(unbumped(params, oneBuild)).toHaveLength(2);
    expect(unbumped(params, wholeProduct)).toEqual([unbumped(params, oneBuild)[1]]);
    expect(unbumped(params, wholeProduct)[0]).toMatch(/past the first$/);
  });
});

describe("a chip and where the list is asked", () => {
  it("draws none for a filter the selection leaves off the request", () => {
    const params = new URLSearchParams("beneath=openssl&differs=1&state=undecided");
    const keys = (scope: { product: string; branch_or_tag: string; variant: string }) =>
      activeFilters(params, undefined, scope).map((chip) => chip.key);
    expect(keys({ product: "", branch_or_tag: "", variant: "" })).toEqual(["state"]);
    expect(keys({ product: "sonic", branch_or_tag: "", variant: "" })).toEqual([
      "state",
      "differs",
    ]);
    expect(keys({ product: "sonic", branch_or_tag: "master", variant: "broadcom" })).toEqual([
      "state",
      "beneath",
      "differs",
    ]);
  });

  it("draws one subtree root where the address names both", () => {
    const params = new URLSearchParams("beneath=openssl&beneath_purl=pkg:github/a/b");
    expect(activeFilters(params).map((chip) => chip.key)).toEqual(["beneath"]);
    expect(listQuery(params)).not.toHaveProperty("beneath_purl");
  });

  it("widens to the whole build when that root's chip is removed, or every chip is", () => {
    const params = new URLSearchParams("beneath=openssl&beneath_purl=pkg:github/a/b");
    const chip = activeFilters(params).find((each) => each.key === "beneath");
    expect(chip).toBeDefined();
    if (!chip) return;
    expect(without(params, chip).toString()).toBe("");
    expect(withoutAny(params).toString()).toBe("");
  });
});

describe("clearing every chip of an address carrying a value the list does not send", () => {
  it("takes that value out too", () => {
    const cleared = withoutAny(new URLSearchParams("state=bogus&open_for=0&sort=age"));
    expect(cleared.toString()).toBe("sort=age");
  });
});
