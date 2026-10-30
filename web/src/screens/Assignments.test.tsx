// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Assignments } from "./Assignments";
import { screen, serve, settle, mounted } from "../test/mount";
import { remember } from "../app/scope";
import { reaching, readingDependencies } from "../test/reach";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] };

const HELD = {
  vulnerability: "clang-tidy/leak",
  component: "frr",
  version: "8.5",
  product: "sonic",
  branch_or_tag: "master",
  variant: "broadcom",
  occurrences: 1,
  builds: 1,
};

async function drawn(row: Record<string, unknown>) {
  serve((path) => {
    if (path === "/v1/session/me") return { data: me };
    if (path === "/v1/people/{identity}/assignments") return { data: { items: [row], total: 1 } };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Assignments />, "/assignments"));
  await settle();
  return mount.host().querySelector<HTMLAnchorElement>("td a")?.getAttribute("href");
}

describe("a code finding in the work somebody holds", () => {
  it("opens the code finding's page and says it is a code finding", async () => {
    const to = await drawn({ ...HELD, occurrence: "abc" });
    expect(to).toBe("/products/sonic/branches-and-tags/master/variants/broadcom/code-findings/abc");
    expect(mount.host().textContent).toContain("code finding");
  });

  it("opens a finding's page where the row is no code finding", async () => {
    const to = await drawn({ ...HELD, vulnerability: "CVE-2026-1" });
    expect(to).not.toContain("/code-findings/");
  });
});

describe("nobody else holding anything in a product", () => {
  afterEach(() => window.sessionStorage.clear());

  async function linked(reads_security_testing: boolean) {
    remember({ product: "sonic" });
    serve((path) => {
      if (path === "/v1/session/me")
        // A reader of disclosed findings there, so who else holds what is drawn.
        return {
          data: {
            ...me,
            reach: [{ product: "sonic", reads_public: true, reads_security_testing }],
          },
        };
      if (path === "/v1/assignments") return { data: [] };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Assignments />, "/assignments?tab=people"));
    await settle();
    return Array.from(mount.host().querySelectorAll("a")).find((each) =>
      each.textContent?.startsWith("Unassigned code findings"),
    );
  }

  it("links the product's code findings nobody holds", async () => {
    const link = await linked(true);
    expect(link?.getAttribute("href")).toBe("/products/sonic/code-findings?assigned=nobody");
  });

  it("links no code findings for somebody who reads no security testing material", async () => {
    expect(await linked(false)).toBeUndefined();
  });
});

describe("what is assigned to the reader, one family at a time", () => {
  afterEach(() => window.sessionStorage.clear());

  // The reader's own lists, answered per family: two dependency findings and
  // three code findings, so a summed figure would read five.
  async function own(reach: unknown[], held: { dependency: number; code: number }) {
    const asked: string[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") return { data: { ...me, reach } };
      if (path === "/v1/people/{identity}/assignments") {
        const family = (init as { params: { query: { family: "dependency" | "code" } } }).params
          .query.family;
        asked.push(family);
        return { data: { items: [], total: held[family] } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Assignments />, "/assignments"));
    await settle();
    const headed = Array.from(mount.host().querySelectorAll("h3")).map((each) =>
      (each.textContent ?? "").trim(),
    );
    return { headed, asked, text: mount.host().textContent ?? "" };
  }

  it("counts each family apart where the reader reads both", async () => {
    const got = await own(
      [
        reaching("sonic", {
          may_see: true,
          reads_public: true,
          reads_private: true,
          reads_security_testing: true,
        }),
      ],
      { dependency: 2, code: 3 },
    );
    expect(got.headed).toEqual(["Dependency findings 2", "Code findings 3"]);
    expect(got.asked.sort()).toEqual(["code", "dependency"]);
    expect(got.text).not.toContain("5");
  });

  it("draws no code findings for a reader of none who holds none", async () => {
    const got = await own([readingDependencies("sonic")], { dependency: 2, code: 0 });
    expect(got.headed).toEqual(["Dependency findings 2"]);
  });

  it("counts code findings a reader of none holds", async () => {
    const got = await own([readingDependencies("sonic")], { dependency: 0, code: 1 });
    expect(got.headed).toEqual(["Dependency findings 0", "Code findings 1"]);
  });

  it("says a family is read elsewhere rather than drawing a zero", async () => {
    remember({ product: "sonic" });
    const got = await own(
      [
        readingDependencies("sonic"),
        reaching("other", { may_see: true, reads_security_testing: true }),
      ],
      { dependency: 2, code: 0 },
    );
    expect(got.headed).toEqual(["Dependency findings 2", "Code findings"]);
    expect(got.text).toContain("You don't read code findings in sonic.");
  });

  it("says nothing is assigned to a reader of neither family who holds nothing", async () => {
    const got = await own([], { dependency: 0, code: 0 });
    expect(got.headed).toEqual([]);
    expect(got.text).toContain("Nothing is assigned to you.");
  });
});
