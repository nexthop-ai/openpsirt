// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Assignments } from "./Assignments";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] };

const HELD = {
  vulnerability: "clang-tidy/leak",
  component: "frr",
  version: "8.5",
  product: "sonic",
  stream: "master",
  variant: "broadcom",
  places: 1,
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

describe("a lead in the work somebody holds", () => {
  it("opens the lead's page and says it is a lead", async () => {
    const to = await drawn({ ...HELD, place: "abc" });
    expect(to).toBe("/products/sonic/streams/master/variants/broadcom/leads/abc");
    expect(mount.host().textContent).toContain("lead");
  });

  it("opens a finding's page where the row is no lead", async () => {
    const to = await drawn({ ...HELD, vulnerability: "CVE-2026-1" });
    expect(to).not.toContain("/leads/");
  });
});
