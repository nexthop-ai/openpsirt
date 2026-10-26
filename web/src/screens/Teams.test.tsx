// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Teams } from "./Teams";
import { Person } from "./Person";
import { act } from "react";
import { handedBack } from "../api/intake";
import { answer, client, screen, serve, settle, mounted, watchInvalidations } from "../test/mount";

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

  for (const [act_, control] of [
    ["retiring a team", "Retire"],
    ["taking somebody off a team", "Take alice off this team"],
  ] as const) {
    it(`refreshes the lists of held work after ${act_}, which hands work back`, async () => {
      deployment(true);
      const sent = answer("DELETE", () => ({ status: 204 }));
      const queries = client();
      const invalidated = watchInvalidations(queries);
      mount.render(screen(<Teams />, "/", "*", queries));
      await settle();
      const button = [...mount.host().querySelectorAll("button")].find(
        (one) => one.textContent?.trim() === control || one.title === control,
      );
      expect(button).toBeDefined();
      await act(async () => button?.click());
      await settle();
      expect(sent()).toHaveLength(1);
      expect(invalidated()).toEqual(expect.arrayContaining(["teams", ...handedBack]));
    });
  }

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

  it("refreshes the lists of held work after a departure, which hands work back", async () => {
    deployment(true);
    const sent = answer("PUT", () => ({ data: { released: 0, since: "" } }));
    const queries = client();
    const invalidated = watchInvalidations(queries);
    mount.render(screen(<Person />, "/access/alice", "/access/:identity", queries));
    await settle();
    await act(async () => leave()?.click());
    await settle();
    expect(sent()).toHaveLength(1);
    expect(invalidated()).toEqual(expect.arrayContaining(["people", ...handedBack]));
  });

  it("holds recording a departure back from an auditor, and says why", async () => {
    deployment(false);
    mount.render(screen(<Person />, "/access/alice", "/access/:identity"));
    await settle();
    expect(leave()?.disabled).toBe(true);
    expect(leave()?.title).toContain("administrator");
  });
});
