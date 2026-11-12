// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { belongTo } from "../app/drafts";
import { RecordFlaw, unpicked } from "./RecordFlaw";
import { change, pick, press, tick } from "../test/controls";
import { accept, mounted, screen, serve, settle, type Sent } from "../test/mount";
import { api } from "../api/client";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  belongTo("oidc:ana");
});

afterEach(() => vi.restoreAllMocks());

// Somebody who may record a flaw at either visibility in sonic.
function serving(rights: { may_hide: boolean; triages_public: boolean }) {
  serve((path) => {
    if (path === "/v1/session/me") {
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: false,
          kind: "person",
          reach: [{ product: "sonic", name: "sonic", ...rights }],
        },
      };
    }
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }] } };
    if (path === "/v1/products/{product}/branches-and-tags") {
      return { data: { items: [{ name: "master", kind: "branch" }] } };
    }
    if (path === "/v1/products/{product}/variants")
      return { data: { items: [{ name: "broadcom" }] } };
    return { data: { items: [], total: 0 } };
  });
  return accept((path) =>
    path === "/v1/products/{product}/findings"
      ? { status: 201, data: { identifier: "OPENPSIRT-2026-1" } }
      : undefined,
  );
}

async function fillIn() {
  mount.render(screen(<RecordFlaw />, "/record-a-flaw?product=sonic"));
  await settle();
  pick(mount.host(), "Found here");
  pick(mount.host(), "Record as a flaw now");
  await settle();
  tick(mount.host(), "master");
  tick(mount.host(), "broadcom");
  change(mount.host().querySelector("textarea"), "The socket answers before anyone signs in.");
  await settle();
}

function recorded(sent: Sent[]): Record<string, unknown> {
  const found = sent.find(([path]) => path === "/v1/products/{product}/findings");
  if (!found) throw new Error("nothing was recorded");
  return (found[1] as { body: Record<string, unknown> }).body;
}

describe("recording a flaw", () => {
  it("records it undisclosed when the disclosure control is left alone", async () => {
    const sent = serving({ may_hide: true, triages_public: true });
    await fillIn();
    await press(mount.host(), "Record flaw, undisclosed");
    await settle();
    const body = recorded(sent());
    expect(body).not.toHaveProperty("disclosed");
    expect(body).toMatchObject({
      builds: [{ branch_or_tag: "master", variant: "broadcom" }],
      summary: "The socket answers before anyone signs in.",
      found_here: true,
    });
  });

  it("forgets the description once the flaw is recorded, so the next one opens empty", async () => {
    const sent = serving({ may_hide: true, triages_public: true });
    await fillIn();
    const drafts = () =>
      Object.keys(window.localStorage).filter((key) => key.endsWith(":record:sonic"));
    expect(drafts()).not.toEqual([]);
    await press(mount.host(), "Record flaw, undisclosed");
    await settle();
    expect(sent()).not.toEqual([]);
    expect(drafts()).toEqual([]);
  });

  it("forgets a version picked for a component once the builds change", async () => {
    serving({ may_hide: true, triages_public: true });
    const sent = vi.spyOn(api, "POST").mockImplementation((async (_path: string, init: unknown) => {
      const body = (init as { body: { version?: string } }).body;
      if (body.version === undefined && (init as { body: { component?: string } }).body.component) {
        return {
          error: {
            detail: "more than one component is named openssl",
            errors: [
              { location: "component", message: "1.1.1" },
              { location: "component", message: "3.0.2" },
            ],
          },
          response: new Response(null, { status: 409 }),
        };
      }
      return {
        data: { identifier: "OPENPSIRT-2026-1" },
        response: new Response(null, { status: 201 }),
      };
    }) as never);
    await fillIn();
    change(mount.host().querySelector<HTMLInputElement>("#rec-component"), "openssl");
    await press(mount.host(), "Record flaw, undisclosed");
    await settle();
    await press(mount.host(), "1.1.1");
    expect(mount.host().textContent).toContain("Recording against 1.1.1");
    tick(mount.host(), "master");
    tick(mount.host(), "master");
    await settle();
    expect(mount.host().textContent).not.toContain("Recording against");
    await press(mount.host(), "Record flaw, undisclosed");
    await settle();
    const last = sent.mock.calls.at(-1) as unknown as Sent;
    expect((last[1] as { body: Record<string, unknown> }).body).not.toHaveProperty("version");
  });

  it("records it public only once somebody picks public", async () => {
    const sent = serving({ may_hide: true, triages_public: true });
    await fillIn();
    pick(mount.host(), "Public");
    await press(mount.host(), "Record flaw");
    await settle();
    expect(recorded(sent())).toMatchObject({ disclosed: true });
  });

  it("records it public for somebody who may record nothing else", async () => {
    const sent = serving({ may_hide: false, triages_public: true });
    mount.render(screen(<RecordFlaw />, "/record-a-flaw?product=sonic"));
    await settle();
    pick(mount.host(), "Found here");
    await settle();
    tick(mount.host(), "master");
    tick(mount.host(), "broadcom");
    change(mount.host().querySelector("textarea"), "A public flaw.");
    await settle();
    await press(mount.host(), "Record flaw");
    await settle();
    expect(recorded(sent())).toMatchObject({ disclosed: true });
  });

  it("forgets a choice of public when the product changes", async () => {
    serving({ may_hide: true, triages_public: true });
    await fillIn();
    pick(mount.host(), "Public");
    expect(mount.host().textContent).toContain("Record flaw");
    change(mount.host().querySelector<HTMLSelectElement>("#rec-product"), "");
    change(mount.host().querySelector<HTMLSelectElement>("#rec-product"), "sonic");
    await settle();
    const card = Array.from(mount.host().querySelectorAll('[role="radio"]')).find(
      (each) => each.querySelector("b")?.textContent === "Undisclosed",
    );
    expect(card?.getAttribute("aria-checked")).toBe("true");
  });
});

const read = { isPending: false, isError: false };

describe("an empty list of builds to pick from", () => {
  it("asks for a product before anything else", () => {
    expect(unpicked("", { ...read, isError: true })).toBe("Pick a product first");
  });

  it("says a failed read failed rather than that nothing is declared", () => {
    expect(unpicked("sonic", { ...read, isError: true })).toBe("Could not be read");
  });

  it("says nothing is declared only once the read has answered", () => {
    expect(unpicked("sonic", { ...read, isPending: true })).toBe("Reading…");
    expect(unpicked("sonic", read)).toBe("Nothing is declared here yet");
  });
});
