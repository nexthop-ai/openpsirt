// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Assignments } from "./Assignments";
import { screen, serve, settle, mounted } from "../test/mount";
import { remember } from "../app/scope";

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

describe("nobody else holding anything in a product", () => {
  afterEach(() => window.sessionStorage.clear());

  async function linked(reads_internal: boolean) {
    remember({ product: "sonic" });
    serve((path) => {
      if (path === "/v1/session/me")
        return { data: { ...me, reach: [{ product: "sonic", reads_internal }] } };
      if (path === "/v1/assignments") return { data: [] };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Assignments />, "/assignments?tab=people"));
    await settle();
    return Array.from(mount.host().querySelectorAll("a")).find((each) =>
      each.textContent?.startsWith("Unassigned leads"),
    );
  }

  it("links the product's leads nobody holds", async () => {
    const link = await linked(true);
    expect(link?.getAttribute("href")).toBe("/products/sonic/leads?assigned=nobody");
  });

  it("links no leads for somebody who reads no internal material", async () => {
    expect(await linked(false)).toBeUndefined();
  });
});
