// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Person } from "./Person";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("one person's roles", () => {
  it("names a role held across every product as every product", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "me", name: "Me", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/people/{identity}") {
        return {
          data: {
            identity: "alice",
            holds: [
              { everywhere: true, role: "private-triage", effective: true, source: "assigned" },
              { product: "sonic", role: "approver", effective: true, source: "assigned" },
            ],
            record: { proposed: 0, approved: 0, withdrawn: 0 },
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Person />, "/access/alice", "/access/:identity"));
    await settle();
    const rows = Array.from(mount.host().querySelectorAll("tbody tr")).map(
      (row) => row.querySelector("td")?.textContent,
    );
    expect(rows).toContain("every product");
    expect(rows).toContain("sonic");
  });
});
