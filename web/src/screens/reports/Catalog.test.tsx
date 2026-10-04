// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { location, mounted, screen, serve, settle } from "../../test/mount";
import { onAskForScope } from "../../app/scope";
import { Scope } from "../../app/Scope";
import { Catalog } from "./Catalog";
import { Report } from "./Report";

const mount = mounted();

afterEach(() => {
  vi.restoreAllMocks();
});

// The control a catalog row draws for its name.
function row(name: string): HTMLElement {
  const found = [...mount.host().querySelectorAll<HTMLElement>(".catalog-name > *")].find(
    (each) => each.querySelector(".name")?.textContent === name || each.textContent === name,
  );
  if (!found) throw new Error(`no catalog row is named ${name}`);
  return found;
}

describe("a catalog entry that needs a scope", () => {
  it("says what it needs apart from what it answers, and opens the scope picker", () => {
    mount.render(screen(<Catalog />, "/reports"));
    const compare = row("Release comparison");
    expect(compare.tagName).toBe("BUTTON");
    expect(compare.querySelector(".needs")?.textContent).toBe("Needs a product");

    const opened = vi.fn();
    const stop = onAskForScope(opened);
    act(() => compare.click());
    stop();
    expect(opened).toHaveBeenCalledTimes(1);
  });

  it("opens the picker in the scope bar", async () => {
    serve(() => undefined);
    // The bar brings itself into view as it opens, and jsdom draws no layout
    // to scroll.
    const kept = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollIntoView");
    const scroll = vi.fn();
    HTMLElement.prototype.scrollIntoView = scroll;
    try {
      mount.render(
        screen(
          <>
            <Scope />
            <Catalog />
          </>,
          "/reports",
        ),
      );
      act(() => row("Release comparison").click());
      await settle();
      const bar = mount.host().querySelector(".scopebar");
      expect(bar?.querySelector(".scope")?.getAttribute("aria-expanded")).toBe("true");
      expect(bar?.querySelector(".picker")?.classList.contains("open")).toBe(true);
      expect(scroll).toHaveBeenCalledTimes(1);
    } finally {
      if (kept) Object.defineProperty(HTMLElement.prototype, "scrollIntoView", kept);
      else delete (HTMLElement.prototype as Partial<HTMLElement>).scrollIntoView;
    }
  });

  it("asks for a whole build where its screen is about one", () => {
    mount.render(screen(<Catalog />, "/products/sonic/streams/master"));
    expect(row("Release comparison").tagName).toBe("A");
    expect(row("Pending upgrades").querySelector(".needs")?.textContent).toBe("Needs a build");
  });

  it("is a link once the scope holds what it needs", () => {
    mount.render(screen(<Catalog />, "/products/sonic/streams/master/variants/broadcom"));
    const upgrades = row("Pending upgrades");
    expect(upgrades.tagName).toBe("A");
    expect(upgrades.getAttribute("href")).toBe(
      "/products/sonic/streams/master/variants/broadcom/pending-upgrades",
    );
  });
});

describe("a report reached at the name it had before", () => {
  // A link to it sits in messages already sent and notifications already
  // stored, and the window it asked for is what makes the page hold what
  // raised the alert.
  it("opens the report under its name now, with the window it asked for", async () => {
    serve(() => undefined);
    mount.render(screen(<Report />, "/reports/rubber-stamp?days=3650", "/reports/:report"));
    await settle();
    expect(location()).toBe("/reports/approval-quality?days=3650");
  });

  it("returns to the catalog for a name nothing ever held", async () => {
    mount.render(screen(<Report />, "/reports/nothing-by-this-name", "/reports/:report"));
    await settle();
    expect(location()).toBe("/reports");
  });
});
