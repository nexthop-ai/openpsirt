// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { describe, expect, it } from "vitest";
import { Incidents } from "./Incidents";
import { accept, answer, screen, serve, settle, mounted, type Sent } from "../test/mount";
import { change, labeled, only, press, tick } from "../test/controls";
import { readingDependencies } from "../test/reach";

const mount = mounted();

const standing = (id: number, product: string, vulnerability: string) => ({
  id,
  product,
  product_name: product.toUpperCase(),
  vulnerability,
  standing: true,
  known_at: "2026-09-01T00:00:00Z",
  grounds: "Seen in the field.",
  windows: [],
  told: [
    {
      id,
      recipient: `${product} regulator`,
      told_at: "2026-09-02T00:00:00Z",
      said: "Reported.",
    },
  ],
  fixes: [
    {
      id,
      release: `${product}-2.0`,
      release_name: `${product}-2.0`,
      released_on: "2026-09-10",
      named_at: "2026-09-03T00:00:00Z",
      open: false,
      scanned: false,
    },
  ],
});

function shelf() {
  serve((asked) => {
    if (asked === "/v1/incidents") {
      return {
        data: {
          items: [standing(1, "sonic", "CVE-2026-0001"), standing(2, "edge", "CVE-2026-0002")],
        },
      };
    }
    if (asked === "/v1/session/me") {
      // A reader of dependency findings in both products, whose shelf it is.
      const reach = ["sonic", "edge"].map((product) => readingDependencies(product));
      return { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach } };
    }
    return { data: { items: [], total: 0 } };
  });
}

describe("the Incidents screen", () => {
  it("narrows to the product the address names, and offers every product back", async () => {
    shelf();
    mount.render(screen(<Incidents />, "/incidents?product=sonic"));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("CVE-2026-0001");
    expect(text).not.toContain("CVE-2026-0002");
    // A record is narrowed whole: the notices and fix releases it carries go
    // with it.
    expect(text).toContain("sonic regulator");
    expect(text).toContain("sonic-2.0");
    expect(text).not.toContain("edge regulator");
    expect(text).not.toContain("edge-2.0");
    expect(text).toContain("Incidents on SONIC");
    expect(mount.host().querySelector('a[href="/incidents"]')?.textContent).toBe("every product");
  });

  it("lists every product's records where the address names none", async () => {
    shelf();
    mount.render(screen(<Incidents />, "/incidents"));
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("CVE-2026-0001");
    expect(text).toContain("CVE-2026-0002");
  });
});

// A reader of the product's dependency findings, who may triage there or not.
const can = (product: string, mayTriage: boolean) => ({
  ...readingDependencies(product),
  name: product.toUpperCase(),
  may_triage: mayTriage,
});

function serving(reach: ReturnType<typeof can>[]) {
  return serve((path) =>
    path === "/v1/session/me"
      ? { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach } }
      : { data: { items: [], total: 0 } },
  );
}

function button(label: string): HTMLButtonElement | undefined {
  return Array.from(mount.host().querySelectorAll<HTMLButtonElement>(".screen-head button")).find(
    (each) => each.textContent?.trim() === label,
  );
}

function pick(select: HTMLSelectElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set?.call(select, value);
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

function type(field: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto =
    field instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
}

describe("recording an incident from its own screen", () => {
  it("sends the request a finding sends, for the product and issue picked", async () => {
    const asked = serving([can("sonic", true), can("other", false)]);
    const sent = accept(() => ({ status: 201, data: {} }));
    mount.render(screen(<Incidents />));
    await settle();

    act(() => button("Record an incident")?.click());
    const select = mount.host().querySelector<HTMLSelectElement>(".card select");
    // Only a product the reader triages is offered: the server refuses the rest.
    expect(Array.from(select?.options ?? []).map((each) => each.value)).toEqual(["", "sonic"]);
    act(() => pick(select!, "sonic"));
    act(() => type(mount.host().querySelector<HTMLInputElement>("input[list]")!, " CVE-2026-1 "));
    await settle();
    // An attack is often on a shipped tag or a release past its end, so the
    // suggestions ask past every default the findings list applies.
    const suggested = (asked.mock.calls as unknown as Sent[]).find(
      ([path]) => path === "/v1/products/{product}/findings",
    );
    expect(suggested?.[1]).toMatchObject({
      params: {
        path: { product: "sonic" },
        query: {
          q: "CVE-2026-1",
          on: ["branch", "tag"],
          support: ["in-support", "past-eol"],
          below_minimum_severity: true,
        },
      },
    });
    act(() =>
      type(mount.host().querySelector<HTMLTextAreaElement>("#grounds")!, "A customer saw it"),
    );
    const record = Array.from(
      mount.host().querySelectorAll<HTMLButtonElement>(".card button"),
    ).find((each) => each.textContent === "Record");
    expect(record?.disabled).toBe(false);
    act(() => record?.click());
    await settle();

    const [path, init] = sent()[0] ?? [];
    expect(path).toBe("/v1/products/{product}/issues/{issue}/incidents");
    expect(init).toMatchObject({
      params: { path: { product: "sonic", issue: "CVE-2026-1" } },
      body: { grounds: "A customer saw it" },
    });
  });

  it("offers the control to nobody who triages no product", async () => {
    serving([can("sonic", false)]);
    mount.render(screen(<Incidents />));
    await settle();
    expect(button("Record an incident")).toBeUndefined();
    expect(mount.host().textContent).toContain("No incidents are recorded.");
  });
});

describe("the response windows an administrator declares", () => {
  // One window limited to a product and counted from another's first notice,
  // with a warning, and the window it counts from.
  const WINDOWS = [
    {
      id: 1,
      name: "Early warning",
      hours: 24,
      lead_hours: 6,
      products: ["sonic"],
      from: 2,
      from_name: "Report",
      declared_at: "2026-09-01T00:00:00Z",
    },
    { id: 2, name: "Report", hours: 72, declared_at: "2026-09-01T00:00:00Z" },
  ];

  function declared() {
    serve((path) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "root", name: "Root", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/response-windows") return { data: { items: WINDOWS } };
      if (path === "/v1/products")
        return { data: { items: [{ name: "sonic" }, { name: "edge" }] } };
      return { data: { items: [], total: 0 } };
    });
  }

  const card = () => {
    const found = Array.from(mount.host().querySelectorAll<HTMLElement>(".card")).find(
      (each) => each.querySelector("h3")?.textContent === "Response windows",
    );
    if (!found) throw new Error("no response windows card");
    return found;
  };
  const counted = () => {
    const label = Array.from(card().querySelectorAll("label")).find(
      (each) => each.querySelector("span")?.textContent === "Counted from",
    );
    return label?.querySelector("select") ?? null;
  };

  // Presses the link on the line naming the window.
  async function onLine(window: string, label: string) {
    const line = Array.from(card().querySelectorAll("p")).find((each) =>
      each.textContent?.startsWith(`${window} `),
    );
    if (!line) throw new Error(`no line for ${window}`);
    await press(line, label);
  }

  it("declares a window with every field the form holds", async () => {
    declared();
    const sent = accept(() => ({ status: 201, data: {} }));
    mount.render(screen(<Incidents />));
    await settle();
    change(labeled(card(), "Name"), "Notify");
    change(labeled(card(), "Length, hours"), "48");
    change(labeled(card(), "Warn, hours before end"), "12");
    change(counted(), "fix");
    tick(card(), "edge");
    await press(card(), "Add window");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/response-windows");
    expect(init.body).toEqual({
      name: "Notify",
      hours: 48,
      lead_hours: 12,
      products: ["edge"],
      from_fix: true,
    });
  });

  it("restates a window's products and start when only its name changes", async () => {
    declared();
    const sent = answer("PUT", () => ({ data: {} }));
    mount.render(screen(<Incidents />));
    await settle();
    await onLine("Early warning", "Edit");
    change(labeled(card(), "Name"), "First warning");
    await press(card(), "Save");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/response-windows/{id}");
    expect(init.params?.path).toEqual({ id: 1 });
    expect(init.body).toEqual({
      name: "First warning",
      hours: 24,
      lead_hours: 6,
      products: ["sonic"],
      from: 2,
    });
  });

  it("sends no warning where its field is cleared", async () => {
    declared();
    const sent = answer("PUT", () => ({ data: {} }));
    mount.render(screen(<Incidents />));
    await settle();
    await onLine("Early warning", "Edit");
    change(labeled(card(), "Warn, hours before end"), "");
    await press(card(), "Save");
    await settle();
    expect(only(sent)[1].body).toEqual({
      name: "Early warning",
      hours: 24,
      products: ["sonic"],
      from: 2,
    });
  });

  it("retires the window on whose line it is pressed", async () => {
    declared();
    const sent = answer("DELETE", () => ({ status: 204 }));
    mount.render(screen(<Incidents />));
    await settle();
    await onLine("Report", "Retire");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/response-windows/{id}");
    expect(init.params?.path).toEqual({ id: 2 });
  });
});

describe("the releases named as carrying an incident's fix", () => {
  function told() {
    serve((path) => {
      if (path === "/v1/incidents") {
        const incident = standing(4, "sonic", "CVE-2026-0004");
        const fixes = incident.fixes.map((fix) => ({ ...fix, id: 40 }));
        return { data: { items: [{ ...incident, fixes, may_tell: true }] } };
      }
      if (path === "/v1/session/me") {
        const reach = [readingDependencies("sonic")];
        return { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach } };
      }
      return { data: { items: [], total: 0 } };
    });
  }

  it("names the release typed, trimmed, on the incident", async () => {
    told();
    const sent = accept(() => ({ status: 201, data: {} }));
    mount.render(screen(<Incidents />));
    await settle();
    await press(mount.host(), "Name a fix release");
    change(mount.host().querySelector<HTMLInputElement>("#fix-4"), " sonic-2.1 ");
    await press(mount.host(), "Name");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/incidents/{id}/fixes");
    expect(init.params?.path).toEqual({ id: 4 });
    expect(init.body).toEqual({ release: "sonic-2.1" });
  });

  it("withdraws the release on whose line it is pressed", async () => {
    told();
    const sent = answer("DELETE", () => ({ status: 204 }));
    mount.render(screen(<Incidents />));
    await settle();
    await press(mount.host(), "Withdraw");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/incidents/{id}/fixes/{fix}");
    expect(init.params?.path).toEqual({ id: 4, fix: 40 });
  });
});
