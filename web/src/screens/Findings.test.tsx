// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Findings } from "./Findings";
import { readingDependencies } from "../test/reach";
import { location, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const me = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person",
  reach: [readingDependencies("sonic")],
};

async function draw(address: string) {
  serve((path) => (path === "/v1/session/me" ? { data: me } : { data: { items: [], total: 0 } }));
  mount.render(screen(<Findings />, address, "/findings"));
  await settle();
}

const buttons = () => Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button"));
const chip = (text: string) => buttons().find((each) => each.textContent?.includes(text));
// The chips above the list, each as "Label: value", without the clear-all.
const chips = () =>
  Array.from(mount.host().querySelectorAll<HTMLButtonElement>(".narrowed button.chip")).map(
    (each) => (each.textContent ?? "").replace("×", "").trim(),
  );
const query = () => new URLSearchParams(location().split("?")[1] ?? "");

describe("the filters narrowing the findings list", () => {
  // Verified by making the chip's click clear every filter: the decision
  // states go with it and the test fails.
  it("removes one chip's filter and leaves the rest of the address", async () => {
    await draw("/findings?exploited=1&sent_back=1");
    const exploited = chip("Known exploited:");
    expect(exploited, "no chip for known exploited").toBeDefined();
    act(() => exploited?.click());
    await settle();
    expect(query().get("exploited")).toBeNull();
    expect(query().get("sent_back")).toBe("1");
  });

  it.each(["/findings?exploited=1"])("unticks known exploited (%s)", async (address) => {
    await draw(address);
    act(() => chip("More filters")?.click());
    await settle();
    const box = Array.from(mount.host().querySelectorAll("label.check")).find(
      (each) => each.textContent === "Known exploited",
    );
    const input = box?.querySelector<HTMLInputElement>("input");
    expect(input?.checked, "the flag does not read the address as on").toBe(true);
    act(() => input?.click());
    await settle();
    expect(query().get("exploited")).toBeNull();
  });

  // Verified by dropping the offset delete from the list's filter change: the
  // address keeps offset=50 and the test fails on it.
  it("starts a list narrowed from the panel at its first page", async () => {
    await draw("/findings?offset=50");
    act(() => chip("More filters")?.click());
    await settle();
    const box = Array.from(mount.host().querySelectorAll("label.check")).find(
      (each) => each.textContent === "Sent back to its author",
    );
    act(() => box?.querySelector<HTMLInputElement>("input")?.click());
    await settle();
    expect(query().get("sent_back")).toBe("1");
    expect(query().get("offset")).toBeNull();
  });

  // The list's own defaults (release kind, support, planned work) are filters
  // like any other and draw chips, so clearing all has to widen past them
  // rather than drop every parameter and let the defaults come back.
  //
  // Verified by clearing all with an empty address: the default chips are
  // drawn again and the test fails on them.
  it("clears every chip it counts, the list's own defaults included", async () => {
    await draw("/findings?sent_back=1");
    const drawn = chips();
    expect(drawn).toContain("Sent back to its author: only");
    const all = chip(`Clear all ${drawn.length} filters`);
    expect(all, `no clear-all naming ${drawn.length}`).toBeDefined();
    act(() => all?.click());
    await settle();
    expect(chips()).toEqual([]);
    expect(query().get("sent_back")).toBeNull();
  });
});

describe("the findings list's keys", () => {
  const row = {
    product: "sonic",
    branch_or_tag: "master",
    variant: "broadcom",
    vulnerability: "CVE-2026-1",
    component: "openssl",
    version: "3.0.0",
    fold: "openssl@3.0.0",
  };

  async function drawRows() {
    serve((path) => {
      if (path === "/v1/session/me") return { data: me };
      if (path === "/v1/findings")
        return {
          data: {
            items: [row, { ...row, version: "3.0.1", fold: "openssl@3.0.1" }],
            total: 2,
          },
        };
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Findings />, "/findings", "/findings"));
    await settle();
  }

  const at = () => mount.host().querySelector("#findingRows tr.at")?.getAttribute("data-i");
  const press = (on: Element | Document, key: string) =>
    act(() => {
      on.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
    });

  // The row the cursor lands on is brought into view a frame later, and jsdom
  // draws no layout to scroll, so each test records the scrolls and waits for
  // that frame.
  async function scrolledRows(during: () => void): Promise<(string | null)[]> {
    const kept = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollIntoView");
    const scrolled: Element[] = [];
    HTMLElement.prototype.scrollIntoView = function (this: Element) {
      scrolled.push(this);
    };
    try {
      during();
      await new Promise((frame) => requestAnimationFrame(frame));
      return scrolled.map((each) => each.getAttribute("data-i"));
    } finally {
      if (kept) Object.defineProperty(HTMLElement.prototype, "scrollIntoView", kept);
      else delete (HTMLElement.prototype as Partial<HTMLElement>).scrollIntoView;
    }
  }

  it("opens a row marked as from the list across products", async () => {
    await drawRows();
    const link = mount.host().querySelector<HTMLAnchorElement>("#findingRows a[href*='from=']");
    const from = new URL(link?.getAttribute("href") ?? "", "http://here").searchParams.get("from");
    expect(new URLSearchParams(from ?? "").get("across")).toBe("1");
  });

  it("moves the cursor on an arrow nothing else answers", async () => {
    await drawRows();
    const scrolled = await scrolledRows(() => {
      press(document, "ArrowDown");
      expect(at()).toBe("0");
    });
    expect(scrolled).toEqual(["0"]);
  });

  // Verified by leaving the frame running after the screen goes: the row a
  // later screen draws under the same address is scrolled and the test fails.
  it("drops the scroll to the cursor's row when the screen goes", async () => {
    await drawRows();
    const scrolled = await scrolledRows(() => {
      press(document, "ArrowDown");
      const rows = mount.host().querySelector("#findingRows");
      mount.render(<></>);
      if (rows) document.body.append(rows);
    });
    document.querySelector("body > #findingRows")?.remove();
    expect(scrolled).toEqual([]);
  });

  // Verified by dropping the handler's check of a key already answered: the
  // cursor lands on the first row and the test fails.
  it("leaves the cursor alone when a filter's list opens on an arrow", async () => {
    await drawRows();
    act(() => chip("More filters")?.click());
    await settle();
    const trigger = mount.host().querySelector<HTMLButtonElement>("button.choicesat");
    if (!trigger) throw new Error("no filter list in the panel");
    trigger.focus();
    press(trigger, "ArrowDown");
    await settle();
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(at()).toBeUndefined();
  });
});
