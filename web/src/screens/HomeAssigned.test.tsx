// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Home } from "./Home";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

const ANA = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [],
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
    each.textContent?.includes("Assigned to you"),
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
