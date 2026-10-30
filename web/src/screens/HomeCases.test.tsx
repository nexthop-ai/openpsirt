// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Home } from "./Home";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";
import { readingDependencies } from "../test/reach";

const mount = mounted();

function who(more: Partial<Who>): Who {
  return {
    identity: "ana",
    name: "Ana",
    admin: false,
    kind: "person",
    reach: [],
    outcomes: [],
    ...more,
  } as Who;
}

const OWN = {
  cases: [{ product: "sonic", product_name: "SONiC", issue: "SONIC-2026-1", added_at: "x" }],
  code_findings: [
    {
      product: "sonic",
      branch_or_tag: "master",
      variant: "broadcom",
      occurrence: "abc",
      rule: "clang/unix.Malloc",
      path: "src/a.c",
      flaw: "SONIC-2026-2",
      added_at: "x",
    },
  ],
};

// The front page for one reader, with their own cases answered as given.
async function home(reader: Who, own: unknown = OWN) {
  const asked: string[] = [];
  serve((path) => {
    asked.push(path);
    if (path === "/v1/session/me/cases") return { data: own };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Home who={reader} />));
  await settle();
  const panel = (title: string) =>
    Array.from(mount.host().querySelectorAll(".panel")).find(
      (each) => each.querySelector("h3")?.textContent === title,
    );
  return { asked, panel };
}

describe("a collaborator's own cases on the front page", () => {
  it("lists each case and code finding they were granted, opening the one thing it reaches", async () => {
    const { panel } = await home(who({ collaborates: true }));
    const links = Array.from(panel("Your cases")?.querySelectorAll("a") ?? []).map((each) => [
      each.textContent,
      each.getAttribute("href"),
    ]);
    expect(links).toEqual([
      ["SONIC-2026-1", "/products/sonic/findings?q=SONIC-2026-1"],
      [
        "clang/unix.Malloc",
        "/products/sonic/branches-and-tags/master/variants/broadcom/code-findings/abc",
      ],
    ]);
    expect(panel("Your cases")?.textContent).toContain("recorded as SONIC-2026-2 in sonic");
    expect(panel("Your cases")?.textContent).toContain("in SONiC");
  });

  it("draws them in place of a Records panel opening nothing they hold", async () => {
    const { panel } = await home(who({ collaborates: true }));
    expect(panel("Records")).toBeUndefined();
  });

  it("keeps the Records panel for a collaborator who keeps the records", async () => {
    const { panel } = await home(who({ collaborates: true, audits: true }));
    expect(panel("Records")).toBeDefined();
    expect(panel("Your cases")).toBeDefined();
  });

  it("draws them beside the figures for a collaborator who reads a product", async () => {
    const { panel } = await home(who({ collaborates: true, reach: [readingDependencies("edge")] }));
    expect(panel("Your cases")).toBeDefined();
  });

  it("asks nothing for a reader brought into nothing", async () => {
    const { asked, panel } = await home(who({}));
    expect(asked).not.toContain("/v1/session/me/cases");
    expect(panel("Your cases")).toBeUndefined();
    expect(panel("Records")).toBeDefined();
  });

  it("draws nothing where every grant has ended", async () => {
    const { panel } = await home(who({ collaborates: true }), { cases: [], code_findings: [] });
    expect(panel("Your cases")).toBeUndefined();
  });
});
