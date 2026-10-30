// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Home } from "./Home";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";
import { reaching, readingDependencies } from "../test/reach";

const mount = mounted();

const ANA = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [readingDependencies("sonic")],
  outcomes: [],
} as unknown as Who;

async function drawn(reports: number) {
  serve((path) => {
    if (path === "/v1/people/{identity}/assignments") return { data: { items: [], total: 3 } };
    if (path === "/v1/people/{identity}/assignments/reports")
      return { data: { items: [], total: reports } };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Home who={ANA} />));
  await settle();
  const tile = Array.from(mount.host().querySelectorAll("button.kpi")).find((each) =>
    each.textContent?.includes("Dependency findings assigned to you"),
  );
  return tile?.textContent ?? "";
}

describe("what the front page says somebody holds", () => {
  it("counts the reports they and their teams hold beside their findings", async () => {
    expect(await drawn(2)).toContain("yours and your teams’, and 2 reports");
  });

  it("says nothing of reports where they hold none", async () => {
    expect(await drawn(0)).not.toContain("report");
  });
});

describe("what the front page says somebody holds, one family at a time", () => {
  // The tiles' figures, answered per family: two dependency findings and
  // three code findings.
  async function tiles(who: Who, held: { dependency: number; code: number }) {
    serve((path, init) => {
      if (path === "/v1/people/{identity}/assignments") {
        const family = (init as { params: { query: { family: "dependency" | "code" } } }).params
          .query.family;
        return { data: { items: [], total: held[family] } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Home who={who} />));
    await settle();
    return Array.from(mount.host().querySelectorAll("button.kpi"))
      .filter((each) => each.textContent?.includes("assigned to you"))
      .map((each) => [
        each.querySelector(".l")?.textContent?.split(" · ")[0],
        each.querySelector(".n")?.textContent,
      ]);
  }

  it("draws one figure per family, never their sum", async () => {
    const both = {
      ...ANA,
      reach: [
        reaching("sonic", {
          may_see: true,
          reads_public: true,
          reads_private: true,
          reads_security_testing: true,
        }),
      ],
    } as Who;
    expect(await tiles(both, { dependency: 2, code: 3 })).toEqual([
      ["Dependency findings assigned to you", "2"],
      ["Code findings assigned to you", "3"],
    ]);
  });

  it("draws no code finding figure for a reader of none who holds none", async () => {
    expect(await tiles(ANA, { dependency: 2, code: 0 })).toEqual([
      ["Dependency findings assigned to you", "2"],
    ]);
  });

  it("counts the code findings a reader of none holds", async () => {
    expect(await tiles(ANA, { dependency: 2, code: 1 })).toEqual([
      ["Dependency findings assigned to you", "2"],
      ["Code findings assigned to you", "1"],
    ]);
  });
});

describe("what the front page says each person has in progress", () => {
  it("counts a person's reports with their open findings", async () => {
    serve((path) => {
      if (path === "/v1/assignments")
        return {
          data: {
            items: [
              { person: "ana", person_name: "Ana", team: false, open: 3, overdue: 0, reports: 2 },
            ],
            total: 1,
          },
        };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Home who={ANA} />));
    await settle();
    const panel = Array.from(mount.host().querySelectorAll(".panel")).find(
      (each) => each.querySelector("h3")?.textContent === "In progress",
    );
    expect(panel?.querySelector(".tally")?.textContent).toBe("5");
    expect(panel?.querySelector("li .what")?.textContent).toBe("3 open, 2 reports");
  });
});
