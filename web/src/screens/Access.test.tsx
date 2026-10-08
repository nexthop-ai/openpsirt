// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
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
});
