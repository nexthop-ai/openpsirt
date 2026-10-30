// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Unassigned } from "./Unassigned";
import type { Who } from "../app/session";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { reaching } from "../test/reach";
import { UNOWNED_LIST } from "./list";

const mount = mounted();

function who(reach: Who["reach"]): Who {
  return { identity: "ana", name: "Ana", admin: false, kind: "person", reach, outcomes: [] } as Who;
}

// The screen at `/unassigned`, with four dependency findings and three code
// findings nobody holds.
async function opened(reader: Who) {
  const asked: string[] = [];
  serve((path) => {
    asked.push(path);
    if (path === "/v1/findings") return { data: { items: [], total: 4 } };
    if (path === "/v1/code-findings") return { data: { items: [], total: 3 } };
    return { data: { items: [], total: 0 } };
  });
  mount.render(screen(<Unassigned who={reader} />, "/unassigned"));
  await settle();
  const doors = [...mount.host().querySelectorAll(".panel")].map((each) => [
    each.querySelector("h3")?.textContent,
    each.querySelector(".tally")?.textContent,
    each.querySelector("footer a")?.getAttribute("href"),
  ]);
  return { doors, asked };
}

describe("work nobody holds", () => {
  it("offers each family's list with its own count to a reader of both", async () => {
    const got = await opened(
      who([
        reaching("sonic", {
          may_see: true,
          reads_public: true,
          reads_private: true,
          reads_security_testing: true,
        }),
      ]),
    );
    expect(got.doors).toEqual([
      ["Dependency findings", "4", UNOWNED_LIST],
      ["Code findings", "3", "/code-findings?assigned=nobody"],
    ]);
  });

  it("says which half a reader of disclosed findings alone is counted", async () => {
    await opened(
      who([reaching("sonic", { may_see: true, reads_public: true, reads_security_testing: true })]),
    );
    expect(mount.host().textContent).toContain(
      "Counting disclosed findings, the ones you read here.",
    );
  });

  it("opens the dependency list for a reader of dependency findings alone", async () => {
    const got = await opened(
      who([reaching("sonic", { may_see: true, reads_public: true, reads_private: true })]),
    );
    expect(location()).toBe(UNOWNED_LIST);
    expect(got.asked).not.toContain("/v1/code-findings");
  });

  it("opens the code finding queue for a reader of code findings alone", async () => {
    const got = await opened(who([reaching("sonic", { reads_security_testing: true })]));
    expect(location()).toBe("/code-findings?assigned=nobody");
    expect(got.asked).not.toContain("/v1/findings");
  });
});
