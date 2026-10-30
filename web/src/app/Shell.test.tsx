// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Shell } from "./Shell";
import { location, mounted, screen, serve, settle, type Answer } from "../test/mount";
import type { Who } from "./session";

const mount = mounted();

const who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

// Where the top search lands for a term, given how the issue route answers.
async function searched(term: string, issue: Answer): Promise<string> {
  serve((path) => (path === "/v1/issues/{issue}" ? issue : { data: { items: [], total: 0 } }));
  mount.render(screen(<Shell who={who}>{null}</Shell>, "/start"));
  await settle();
  const box = mount
    .host()
    .querySelector<HTMLInputElement>('input[aria-label="Find an issue, or a component"]');
  if (!box) throw new Error("no top search");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(box, term);
    box.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => box.form?.requestSubmit());
  await settle();
  return location();
}

describe("the top search", () => {
  it("opens an issue somebody here carries", async () => {
    const at = await searched("CVE-2026-1", { data: { items: [{}], total: 1 } });
    expect(at).toContain("CVE-2026-1");
  });

  it("lands on the component chooser for a term no issue here answers to", async () => {
    const at = await searched("openssl", { data: { items: [], total: 0 } });
    expect(at).toBe("/search/openssl");
    expect(mount.host().textContent).not.toContain("could not be looked up");
  });

  it("stays put when the issue could not be read", async () => {
    const at = await searched("openssl", { status: 503 });
    expect(at).toBe("/start");
    expect(mount.host().textContent).toContain("could not be looked up");
  });
});

// The rail as drawn for one reach, at one address.
async function railAt(at: string, reach: Record<string, unknown>[]) {
  window.sessionStorage.clear();
  serve(() => ({ data: { items: [], total: 0 } }));
  mount.render(
    screen(<Shell who={{ ...who, reach: reach as unknown as Who["reach"] }}>{null}</Shell>, at),
  );
  await settle();
}

const entry = (label: string) =>
  [...mount.host().querySelectorAll<HTMLElement>("a, button")].find(
    (each) => each.textContent?.trim() === label,
  );

describe("the code findings entry", () => {
  it("is absent for somebody who reads security testing material nowhere", async () => {
    await railAt("/products/sonic", [{ product: "sonic", reads_private: true }]);
    expect(entry("Security testing")).toBeUndefined();
  });

  it("opens the queue across products where no product is picked", async () => {
    await railAt("/start", [{ product: "sonic", reads_security_testing: true }]);
    expect(entry("Security testing")?.getAttribute("href")).toBe("/code-findings");
  });

  it("declines and says so where the reader may not read security testing material", async () => {
    await railAt("/products/other", [
      { product: "sonic", reads_security_testing: true },
      { product: "other", reads_public: true },
    ]);
    expect(entry("Security testing")?.tagName).toBe("BUTTON");
    expect(entry("Security testing")?.title).toBe("You don't read code findings in other.");
  });

  it("opens the product's queue on the branch and variant picked", async () => {
    await railAt("/products/sonic/branches-and-tags/main/variants/x86", [
      { product: "sonic", reads_security_testing: true },
    ]);
    expect(entry("Security testing")?.getAttribute("href")).toBe(
      "/products/sonic/code-findings?branch_or_tag=main&variant=x86",
    );
  });

  it("opens every build's queue where only the product is picked", async () => {
    await railAt("/products/sonic", [{ product: "sonic", reads_security_testing: true }]);
    expect(entry("Security testing")?.getAttribute("href")).toBe("/products/sonic/code-findings");
  });
});

describe("the dependency findings entry", () => {
  it("names what it lists, and says SCA on hover", async () => {
    await railAt("/products/sonic", [{ product: "sonic", reads_private: true }]);
    expect(entry("Dependency findings")?.title).toBe("SCA");
  });
});

describe("the rail for a reader without dependency findings", () => {
  const securityTestingOnly = [
    {
      product: "sonic",
      may_see: true,
      reads_security_testing: true,
      triages_security_testing: true,
    },
  ];

  it("draws no Dependency findings entry for a reader holding them nowhere", async () => {
    await railAt("/products/sonic", securityTestingOnly);
    expect(entry("Dependency findings")).toBeUndefined();
  });

  it("opens the code findings nobody holds from Unassigned for a reader of code findings alone", async () => {
    await railAt("/products/sonic", securityTestingOnly);
    expect(entry("Unassigned")?.getAttribute("href")).toBe("/code-findings?assigned=nobody");
  });

  it("draws no phone findings tab for a reader holding dependency findings nowhere", async () => {
    await railAt("/products/sonic", securityTestingOnly);
    const tabs = [...mount.host().querySelectorAll(".tabbar a")].map((each) => each.textContent);
    expect(tabs).toContain("Home");
    expect(tabs).not.toContain("Findings");
  });

  it("declines Dependency findings where they are read in another product, saying so", async () => {
    await railAt("/products/sonic", [
      { product: "edge", may_see: true, reads_private: true, reads_public: true },
      { product: "sonic", may_see: true, reads_security_testing: true },
    ]);
    expect(entry("Dependency findings")?.tagName).toBe("BUTTON");
    expect(entry("Dependency findings")?.title).toBe(
      "You don't read dependency findings in sonic.",
    );
  });

  it("asks no dependency count for a product the reader does not read them in", async () => {
    window.sessionStorage.clear();
    const spy = serve(() => ({ data: { items: [], total: 0 } }));
    const reach = [
      { product: "edge", may_see: true, reads_private: true, reads_public: true },
      { product: "sonic", may_see: true, reads_security_testing: true },
    ];
    mount.render(
      screen(
        <Shell who={{ ...who, reach: reach as unknown as Who["reach"] }}>{null}</Shell>,
        "/products/sonic",
      ),
    );
    await settle();
    const asked = (spy.mock.calls as unknown as [string][]).map(([path]) => path);
    expect(asked).toContain("/v1/findings");
    expect(asked).not.toContain("/v1/products/{product}/findings");
  });

  it("draws no Disclosure deadlines for a reader of no undisclosed work", async () => {
    await railAt("/start", securityTestingOnly);
    expect(entry("Disclosure deadlines")).toBeUndefined();
  });

  it("draws no Record a flaw for a reader who may record one nowhere", async () => {
    await railAt("/start", securityTestingOnly);
    expect(entry("Record a flaw")).toBeUndefined();
  });

  it("offers Disclosure deadlines and Record a flaw to a triager of undisclosed work", async () => {
    await railAt("/start", [
      { product: "sonic", may_see: true, reads_private: true, reads_public: true, may_hide: true },
    ]);
    expect(entry("Disclosure deadlines")).toBeDefined();
    expect(entry("Record a flaw")).toBeDefined();
  });

  it("offers Incidents to a reader of no dependency findings, whose own case may be on it", async () => {
    await railAt("/start", securityTestingOnly);
    expect(entry("Incidents")).toBeDefined();
  });

  it("offers Analytics to a reader of no finding, for the coverage reports", async () => {
    await railAt("/start", [{ product: "sonic" }]);
    expect(entry("Analytics")).toBeDefined();
  });

  it("offers Record a flaw to a triager of disclosed work alone, and no Disclosure deadlines", async () => {
    await railAt("/start", [
      { product: "sonic", may_see: true, reads_public: true, triages_public: true },
    ]);
    expect(entry("Record a flaw")).toBeDefined();
    expect(entry("Disclosure deadlines")).toBeUndefined();
  });

  it("says on the Unassigned badge that a disclosed-only reader's count is of disclosed findings", async () => {
    window.sessionStorage.clear();
    serve(() => ({ data: { items: [], total: 4 } }));
    const reach = [{ product: "sonic", may_see: true, reads_public: true }];
    mount.render(
      screen(
        <Shell who={{ ...who, reach: reach as unknown as Who["reach"] }}>{null}</Shell>,
        "/start",
      ),
    );
    await settle();
    const badge = entry("Unassigned4")?.querySelector(".count");
    expect(badge?.getAttribute("title")).toContain(
      "Counting disclosed findings, the ones you read here.",
    );
  });
});

describe("the Unassigned entry, one count per family", () => {
  // The rail with work nobody holds answered per family: four dependency
  // findings and three code findings.
  async function unassigned(reach: Record<string, unknown>[]) {
    window.sessionStorage.clear();
    const asked: string[] = [];
    serve((path) => {
      asked.push(path);
      if (path === "/v1/findings") return { data: { items: [], total: 4 } };
      if (path === "/v1/code-findings") return { data: { items: [], total: 3 } };
      return { data: { items: [], total: 0 } };
    });
    mount.render(
      screen(
        <Shell who={{ ...who, reach: reach as unknown as Who["reach"] }}>{null}</Shell>,
        "/start",
      ),
    );
    await settle();
    const link = [...mount.host().querySelectorAll<HTMLElement>("a")].find((each) =>
      each.textContent?.startsWith("Unassigned"),
    );
    const badges = [...(link?.querySelectorAll(".count") ?? [])].map((each) => [
      each.textContent,
      each.getAttribute("title"),
    ]);
    return { href: link?.getAttribute("href"), badges, asked };
  }

  it("draws each family's badge apart for a reader of both, opening the screen offering both", async () => {
    const got = await unassigned([
      {
        product: "sonic",
        may_see: true,
        reads_public: true,
        reads_private: true,
        reads_security_testing: true,
      },
    ]);
    expect(got.href).toBe("/unassigned");
    expect(got.badges).toEqual([
      ["4", "4 dependency findings nobody holds and nobody has decided"],
      ["3", "3 code findings nobody holds"],
    ]);
  });

  it("asks no code count for a reader of no code finding", async () => {
    const got = await unassigned([
      { product: "sonic", may_see: true, reads_public: true, reads_private: true },
    ]);
    expect(got.asked).not.toContain("/v1/code-findings");
    expect(got.badges.map(([n]) => n)).toEqual(["4"]);
    expect(got.href).toContain("/findings?");
  });

  it("asks no dependency count for a reader of code findings alone", async () => {
    const got = await unassigned([{ product: "sonic", reads_security_testing: true }]);
    expect(got.asked).not.toContain("/v1/findings");
    expect(got.badges.map(([n]) => n)).toEqual(["3"]);
    expect(got.href).toBe("/code-findings?assigned=nobody");
  });
});
