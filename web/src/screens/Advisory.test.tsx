// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Advisory } from "./Advisory";
import { button, change, press } from "../test/controls";
import { answer, mounted, screen, serve, settle, type Sent } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ADDRESS = "/advisories/SONIC-2026-1";
const PATTERN = "/advisories/:advisory";

const covered = {
  product: "sonic",
  vulnerability: "CVE-2026-1",
  summary: "The socket answers before sign-in.",
  added_at: "2026-10-01T00:00:00Z",
};

// One advisory as the server answers it, and the reads beside it.
function serving(advisory: Record<string, unknown>, releases: unknown[] = []) {
  serve((path) => {
    if (path === "/v1/advisories/{advisory}") return { data: advisory };
    if (path === "/v1/advisories/{advisory}/releases") return { data: { items: releases } };
    if (path === "/v1/advisories/{advisory}/issuance") return { data: { items: [] } };
    if (path === "/v1/advisories/{advisory}/document") {
      return {
        data: {
          document: {
            tracking: { id: "SONIC-2026-1", version: "1", status: "draft" },
            distribution: { tlp: { label: "RED" } },
          },
        },
      };
    }
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }] } };
    return { data: { items: [], total: 0 } };
  });
}

const bodyOf = (sent: Sent) => (sent[1] as { body?: unknown }).body;

describe("one advisory", () => {
  it("retitles with the words typed, and only once they differ", async () => {
    serving({ title: "Old", covers: [], agreed: 0, status: "draft" });
    const patched = answer("PATCH", () => ({ data: {} }));
    mount.render(screen(<Advisory />, ADDRESS, PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("Names no flaw");
    expect(button(mount.host(), "Save").disabled).toBe(true);
    change(mount.host().querySelector<HTMLInputElement>(".card input"), "Two flaws in the socket");
    await press(mount.host(), "Save");
    await settle();
    expect(patched().map(bodyOf)).toEqual([{ title: "Two flaws in the socket" }]);
  });

  it("names the flaw typed in the product picked, trimmed", async () => {
    serving({ title: "", covers: [], agreed: 0, status: "draft" });
    const posted = answer("POST", () => ({ data: {} }));
    mount.render(screen(<Advisory />, ADDRESS, PATTERN));
    await settle();
    expect(button(mount.host(), "Name it").disabled).toBe(true);
    change(mount.host().querySelector<HTMLSelectElement>(".card select"), "sonic");
    change(
      mount.host().querySelector<HTMLInputElement>('input[list="advisory-flaws"]'),
      " CVE-2026-2 ",
    );
    await press(mount.host(), "Name it");
    await settle();
    expect(posted()).toEqual([
      [
        "/v1/advisories/{advisory}/issues",
        {
          params: { path: { advisory: "SONIC-2026-1" } },
          body: { product: "sonic", vulnerability: "CVE-2026-2" },
        },
      ],
    ]);
  });

  it("takes off the flaw on the row pressed", async () => {
    serving({ title: "", covers: [covered], agreed: 1, status: "draft" });
    const removed = answer("DELETE", () => ({ data: {} }));
    mount.render(screen(<Advisory />, ADDRESS, PATTERN));
    await settle();
    await press(mount.host(), "Take off");
    await settle();
    expect(removed()[0]?.[1]).toEqual({
      params: { path: { advisory: "SONIC-2026-1", product: "sonic", vulnerability: "CVE-2026-1" } },
    });
  });

  it("marks a release affected, and offers taking agreement back only when there is some", async () => {
    serving({ title: "", covers: [covered], agreed: 0, status: "draft" }, [
      {
        product: "sonic",
        vulnerability: "CVE-2026-1",
        stream: "master",
        variant: "broadcom",
        status: "known_not_affected",
        decided: "known_not_affected",
        covered: { decision: 4, outcome: "not-affected", made_on: [] },
      },
    ]);
    const put = answer("PUT", () => ({ data: {} }));
    mount.render(screen(<Advisory />, ADDRESS, PATTERN));
    await settle();
    expect(mount.host().textContent).toContain("Nobody has agreed to what it says");
    expect(button(mount.host(), "Take every agreement back").disabled).toBe(true);
    expect(button(mount.host(), "Record that it went out").disabled).toBe(true);
    await press(mount.host(), "Mark affected");
    await settle();
    expect(bodyOf(put()[0] as Sent)).toEqual({
      product: "sonic",
      vulnerability: "CVE-2026-1",
      stream: "master",
      variant: "broadcom",
      affected: true,
    });
  });

  it("records that it went out with the revision typed, once somebody has agreed", async () => {
    serving({ title: "", covers: [covered], agreed: 1, status: "final" });
    const posted = answer("POST", () => ({ data: {} }));
    mount.render(screen(<Advisory />, ADDRESS, PATTERN));
    await settle();
    change(
      mount.host().querySelector<HTMLInputElement>('input[placeholder^="What changed"]'),
      " First edition ",
    );
    await press(mount.host(), "Record that it went out");
    await settle();
    expect(posted().map(([path, init]) => [path, (init as { body: unknown }).body])).toEqual([
      ["/v1/advisories/{advisory}/issuance", { summary: "First edition" }],
    ]);
  });
});
