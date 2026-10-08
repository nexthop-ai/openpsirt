// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Teams } from "./Teams";
import { Person } from "./Person";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

function deployment(admin: boolean) {
  serve((path) => {
    if (path === "/v1/session/me") {
      return { data: { identity: "me", name: "Me", admin, kind: "person", reach: [] } };
    }
    if (path === "/v1/teams") {
      return { data: { items: [{ name: "platform", members: admin ? ["alice"] : [] }] } };
    }
    if (path === "/v1/people/{identity}") {
      return {
        data: {
          identity: "alice",
          holds: [],
          record: { proposed: 0, approved: 0, withdrawn: 0 },
        },
      };
    }
    return { data: { items: [], total: 0 } };
  });
}

describe("the teams screen", () => {
  it("offers an administrator every control", async () => {
    deployment(true);
    mount.render(screen(<Teams />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(mount.host().querySelector(".screen-head button")?.textContent).toContain("Add team");
    expect(text).toContain("Retire");
    expect(text).toContain("alice");
  });

  it("offers anybody else no control and no membership it cannot read", async () => {
    deployment(false);
    mount.render(screen(<Teams />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("platform");
    expect(mount.host().querySelector(".screen-head button")).toBeNull();
    expect(text).not.toContain("Retire");
    expect(text).not.toContain("work routed here stays unassigned");
  });
});

describe("one person", () => {
  const leave = () =>
    Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Record that they have left",
    );

  it("offers recording a departure to an administrator", async () => {
    deployment(true);
    mount.render(screen(<Person />, "/access/alice", "/access/:identity"));
    await settle();
    expect(leave()?.disabled).toBe(false);
  });

  it("holds recording a departure back from an auditor, and says why", async () => {
    deployment(false);
    mount.render(screen(<Person />, "/access/alice", "/access/:identity"));
    await settle();
    expect(leave()?.disabled).toBe(true);
    expect(leave()?.title).toContain("administrator");
  });
});
