// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { api } from "../api/client";
import { Access } from "./Access";
import type { Who } from "../app/session";
import { screen, serve, settle, mounted, type Answer } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const admin: Who = {
  identity: "root",
  name: "Root",
  admin: true,
  kind: "person",
  reach: [],
  outcomes: [],
};
const auditor: Who = { ...admin, identity: "audit", admin: false, audits: true };

const alice = {
  identity: "alice",
  holds: [{ product: "sonic", role: "triager", source: "assigned", effective: true }],
};

function deployment(overrides: Record<string, Answer> = {}) {
  serve((path) => {
    if (path in overrides) return overrides[path];
    if (path === "/v1/people") return { data: { items: [alice], total: 1 } };
    if (path === "/v1/roles/mode") return { data: { mode: "direct" } };
    return { data: { items: [], total: 0 } };
  });
}

describe("the access screen", () => {
  it("says the credentials could not be read rather than that none are issued", async () => {
    deployment({ "/v1/keys": { status: 503 } });
    mount.render(screen(<Access who={admin} />));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("The keys and tokens could not be read.");
    expect(text).not.toContain("Nothing is issued.");
  });

  it("says the group bindings could not be read", async () => {
    deployment({ "/v1/roles/bindings": { status: 503 } });
    mount.render(screen(<Access who={admin} />));
    await settle();
    expect(mount.host().textContent).toContain("The group bindings could not be read.");
  });

  it("says where each group mapping is held", async () => {
    deployment({
      "/v1/roles/bindings": {
        data: {
          items: [
            { group: "leads", role: "admin" },
            { group: "psirt", role: "private-read" },
            { group: "kernel", product: "sonic", role: "public-triage" },
          ],
          total: 3,
        },
      },
    });
    mount.render(screen(<Access who={admin} />));
    await settle();
    const rows = [...mount.host().querySelectorAll("tr")].map((row) => row.textContent ?? "");
    expect(rows).toContain("leadsWhole deploymentadmin");
    expect(rows).toContain("psirtEvery productprivate-read");
    expect(rows).toContain("kernelsonicpublic-triage");
  });

  it("offers withdrawing a role only to an administrator", async () => {
    deployment();
    mount.render(screen(<Access who={admin} />));
    await settle();
    expect(mount.host().querySelector('[title="Withdraw this role"]')).not.toBeNull();
  });

  it("offers an auditor no control to withdraw a role", async () => {
    deployment();
    mount.render(screen(<Access who={auditor} />));
    await settle();
    expect(mount.host().textContent).toContain("alice");
    expect(mount.host().querySelector('[title="Withdraw this role"]')).toBeNull();
  });

  it("unbinds a pinned sign-in from the list", async () => {
    deployment({
      "/v1/people": {
        data: {
          items: [{ ...alice, signs_in_by: [{ username: "alice", pinned: true }] }],
          total: 1,
        },
      },
    });
    const sent = vi.spyOn(api, "DELETE").mockResolvedValue({
      data: undefined,
      error: undefined,
      response: new Response(null, { status: 204 }),
    } as never);
    mount.render(screen(<Access who={admin} />));
    await settle();
    const button = [...mount.host().querySelectorAll("button")].find(
      (one) => one.textContent === "Unbind",
    );
    expect(button).toBeDefined();
    await act(async () => button?.click());
    expect(sent).toHaveBeenCalledWith("/v1/people/{identity}/identifier", {
      params: { path: { identity: "alice" } },
    });
  });

  it("offers no unbinding for a name nothing is pinned to", async () => {
    deployment({
      "/v1/people": {
        data: {
          items: [{ ...alice, signs_in_by: [{ username: "alice", pinned: false }] }],
          total: 1,
        },
      },
    });
    mount.render(screen(<Access who={admin} />));
    await settle();
    const labels = [...mount.host().querySelectorAll("button")].map((one) => one.textContent);
    expect(labels).not.toContain("Unbind");
  });

  // A source of roles that could not be read is treated as one that assigns
  // them, because a direct grant made under it is overwritten at the next
  // sign-in.
  it("locks managing and withdrawing roles while the source of roles cannot be read", async () => {
    deployment({ "/v1/roles/mode": { status: 503 } });
    mount.render(screen(<Access who={admin} />));
    await settle();
    const manage = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Manage",
    );
    expect(manage?.disabled).toBe(true);
    expect(manage?.title).toBe("The source of roles could not be read");
    expect(mount.host().querySelector('[title="Withdraw this role"]')).toBeNull();
  });

  it("locks managing roles that provider groups assign", async () => {
    deployment({ "/v1/roles/mode": { data: { mode: "group-bound" } } });
    mount.render(screen(<Access who={admin} />));
    await settle();
    const manage = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Manage",
    );
    expect(manage?.disabled).toBe(true);
    expect(manage?.title).toBe("Roles come from provider groups and would be overwritten");
  });

  it("opens the grant grid for one person where roles are granted here", async () => {
    deployment();
    mount.render(screen(<Access who={admin} />));
    await settle();
    const manage = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Manage",
    );
    expect(manage?.disabled).toBe(false);
    await act(async () => manage?.click());
    await settle();
    expect(mount.host().querySelector(".permgrid")).not.toBeNull();
  });
});
