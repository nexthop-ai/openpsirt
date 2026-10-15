// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Together } from "./Together";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ISSUES =
  "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/issues";

describe("narrowing a bulk decision", () => {
  it("keeps the component it was opened for", async () => {
    const reads = serve(() => ({ data: { items: [], total: 0 } }));
    mount.render(
      screen(
        <Together />,
        "/products/sonic/streams/master/variants/x/components/openssl/decide?version=1.1.1w&ecosystem=deb",
        "/products/:product/streams/:stream/variants/:variant/components/:component/decide",
      ),
    );
    await settle();
    const box = mount.host().querySelector<HTMLInputElement>(".searchbox input");
    if (!box) throw new Error("no narrowing box");
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(
        box,
        "driver",
      );
      box.dispatchEvent(new Event("input", { bubbles: true }));
    });
    act(() => {
      box.form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    await settle();
    const calls = reads.mock.calls as unknown as [string, { params: { query: object } }][];
    const last = calls.filter(([path]) => path === ISSUES).at(-1);
    expect(last?.[1].params.query).toMatchObject({
      contains: "driver",
      version: "1.1.1w",
      ecosystem: "deb",
    });
  });
});

const AT = "/products/sonic/streams/master/variants/x/components/openssl/decide";
const PATTERN = "/products/:product/streams/:stream/variants/:variant/components/:component/decide";

// The issues at the component, as the server pages them, split over two
// pages. The total is what makes a second page exist at all.
function issuesAt(query: { offset?: number }) {
  const every = ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"].map((name, i) => ({
    vulnerability: name,
    places: i + 1,
    severity: "high",
  }));
  const pages: Record<number, typeof every> = { 0: every.slice(0, 3), 500: every.slice(3) };
  return {
    data: {
      items: pages[query.offset ?? 0] ?? [],
      total: 1003,
      findings: 15,
      issue_limit: 4,
      place_limit: 6,
    },
  };
}

async function together() {
  const reads = serve((path, init) =>
    path === ISSUES
      ? issuesAt((init as { params: { query: { offset?: number } } }).params.query)
      : { data: { items: [] } },
  );
  mount.render(screen(<Together />, AT, PATTERN));
  await settle();
  return reads;
}

const tick = (name: string) =>
  act(async () =>
    mount.host().querySelector<HTMLInputElement>(`input[aria-label="Select ${name}"]`)?.click(),
  );
const said = () => mount.host().textContent ?? "";

describe("what a bulk decision would write", () => {
  it("counts the findings each picked issue writes, and warns past the limit", async () => {
    await together();
    await tick("CVE-2");
    expect(said()).toContain("1 issue · 2 findings would be written");
    await tick("CVE-3");
    await tick("CVE-1");
    expect(said()).toContain("3 issues · 6 findings would be written");
    expect(mount.host().querySelector(".alert.warn")).toBeNull();
  });

  it("keeps counting what was picked on an earlier page", async () => {
    await together();
    await tick("CVE-3");
    await act(async () =>
      Array.from(mount.host().querySelectorAll("button"))
        .find((each) => each.textContent === "Next")
        ?.click(),
    );
    await settle();
    await tick("CVE-5");
    // Past the limit only when the first page's places are remembered.
    expect(said()).toContain("2 issues · 8 findings would be written");
    expect(said()).toContain("limit 6 findings");
  });

  it("selects everything matching across pages, and counts it from the server", async () => {
    await together();
    await act(async () =>
      Array.from(mount.host().querySelectorAll("button"))
        .find((each) => each.textContent === "Select all 1,003 matching")
        ?.click(),
    );
    await settle();
    expect(said()).toContain("5 of 1,003 selected");
    expect(said()).toContain("5 issues · 15 findings would be written");
    expect(said()).toContain("limit 4 issues");
  });

  it("lets go of the selection when the list is narrowed", async () => {
    await together();
    await tick("CVE-1");
    const box = mount.host().querySelector<HTMLInputElement>(".searchbox input");
    act(() => {
      box?.form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    await settle();
    expect(said()).toContain("0 of 1,003 selected");
  });
});
