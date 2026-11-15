// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { useSearchParams } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { answer, location, mounted, screen, serve, settle } from "../test/mount";
import { change, only, press, tick } from "../test/controls";
import { PUBLISHED } from "../test/outcomes";
import { Saved } from "./Saved";

const mount = mounted();

// The control as the list holds it: a pick replaces the address.
function Picking() {
  const [, setParams] = useSearchParams();
  return <Saved onBuild={false} onPicked={(next) => setParams(next)} />;
}

// A controlled select moved the way a person moves it.
function pick(select: HTMLSelectElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set?.call(select, value);
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

// A controlled field changed the way a person changes it.
function type(field: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
}

function button(label: string): HTMLButtonElement | undefined {
  return Array.from(mount.host().querySelectorAll<HTMLButtonElement>("button")).find(
    (each) => each.textContent === label,
  );
}

// The person's filters, and every PUT the control sends.
function keeping(items: { name: string; query: string }[]) {
  serve((path) =>
    path === "/v1/session/me/saved-filters" ? { data: { items, total: items.length } } : undefined,
  );
  const put = answer("PUT", () => ({ status: 204 }));
  return () => put() as [string, { body: { query: string } }][];
}

// Saves the list on screen under a name.
async function save(name: string) {
  act(() => button("Save this")?.click());
  const field = mount.host().querySelector<HTMLInputElement>('input[type="text"]');
  if (!field) throw new Error("no name field");
  act(() => type(field, name));
  act(() => button("Save")?.click());
  await settle();
}

describe("a saved filter", () => {
  it("opens within the scope and grouping on screen", async () => {
    keeping([{ name: "kernel", query: "component=linux" }]);
    mount.render(
      screen(
        <Picking />,
        "/f?branch_or_tag=main&severity=critical&variant=x86&opened_by_run=4&view=components",
      ),
    );
    await settle();
    const select = mount.host().querySelector<HTMLSelectElement>("select");
    if (!select) throw new Error("no saved filters control");
    act(() => pick(select, "kernel"));
    await settle();
    expect(location()).toBe(
      "/f?component=linux&branch_or_tag=main&variant=x86&opened_by_run=4&view=components&rule=kernel",
    );
    // Open, because what it keeps is what the list is narrowed by.
    expect(select.value).toBe("kernel");
  });

  it("is kept without its scope, and saying so", async () => {
    const sent = keeping([]);
    mount.render(
      screen(<Saved onBuild={false} onPicked={() => {}} />, "/f?branch_or_tag=main&exploited=1"),
    );
    await settle();
    await save("exploited");
    expect(sent()[0]?.[1].body.query).toBe("exploited=1");
    expect(mount.host().querySelector('[role="status"]')?.textContent).toBe(
      "Saved. Applies to whatever branch and variant you're viewing.",
    );
  });

  it("says so when saved on one build, whose branch and variant are in the path", async () => {
    keeping([]);
    mount.render(screen(<Saved onBuild onPicked={() => {}} />, "/f?exploited=1"));
    await settle();
    await save("exploited");
    expect(mount.host().querySelector('[role="status"]')?.textContent).toBe(
      "Saved. Applies to whatever branch and variant you're viewing.",
    );
  });

  it("says only that it saved where there was no scope to leave out", async () => {
    const sent = keeping([]);
    mount.render(screen(<Saved onBuild={false} onPicked={() => {}} />, "/f?exploited=1"));
    await settle();
    await save("exploited");
    expect(sent()[0]?.[1].body.query).toBe("exploited=1");
    expect(mount.host().querySelector('[role="status"]')?.textContent).toBe("Saved.");
  });
});

describe("a saved filter that prepares a decision", () => {
  async function chosen(outcome: string) {
    serve((path) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", kind: "person", outcomes: PUBLISHED } };
      }
      if (path === "/v1/session/me/saved-filters") return { data: { items: [], total: 0 } };
      return undefined;
    });
    mount.render(screen(<Picking />, "/findings?component=linux"));
    await settle();
    act(() => button("Save this")?.click());
    const field = mount.host().querySelector<HTMLInputElement>('input[type="text"]');
    if (!field) throw new Error("no name field");
    act(() => type(field, "kernel"));
    const box = mount.host().querySelector<HTMLInputElement>('input[type="checkbox"]');
    act(() => box?.click());
    const selects = () => mount.host().querySelectorAll<HTMLSelectElement>("select");
    act(() => pick(selects()[selects().length - 1]!, outcome));
    const reasoning = mount.host().querySelector("textarea");
    if (reasoning) {
      act(() => {
        Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(
          reasoning,
          "the module is not built",
        );
        reasoning.dispatchEvent(new Event("input", { bubbles: true }));
      });
    }
    await settle();
    return selects;
  }

  it("holds Save back until a reason is chosen where the outcome needs one", async () => {
    const selects = await chosen("not-applicable");
    expect(button("Save")?.disabled).toBe(true);
    act(() => pick(selects()[selects().length - 1]!, "component_not_present"));
    expect(button("Save")?.disabled).toBe(false);
  });

  it("offers no reason that needs mitigation text a filter cannot carry", async () => {
    const selects = await chosen("not-applicable");
    const offered = Array.from(selects()[selects().length - 1]!.options).map((each) => each.value);
    expect(offered).toContain("component_not_present");
    expect(offered).not.toContain("inline_mitigations_already_exist");
  });

  // The person's filters and outcomes, and every PUT the control sends.
  function preparing() {
    serve((path) => {
      if (path === "/v1/session/me/saved-filters") return { data: { items: [], total: 0 } };
      if (path === "/v1/session/me") {
        return {
          data: { identity: "ana", name: "Ana", admin: false, kind: "person", outcomes: PUBLISHED },
        };
      }
      return undefined;
    });
    return answer("PUT", () => ({ status: 204 }));
  }

  const field = <T extends Element>(label: string): T => {
    const found = Array.from(mount.host().querySelectorAll("label")).find(
      (each) => each.querySelector(".l")?.textContent === label,
    );
    const control = found?.querySelector<T>("input, select, textarea" as never);
    if (!control) throw new Error(`no field ${label}`);
    return control;
  };

  async function prepared(days: string) {
    mount.render(screen(<Saved onBuild={false} onPicked={() => {}} />, "/f?exploited=1"));
    await settle();
    await press(mount.host(), "Save this");
    change(field<HTMLInputElement>("Call it"), "quarter");
    tick(mount.host(), "And prepare a decision for what it catches");
    change(field<HTMLSelectElement>("It would say"), "not-applicable");
    change(field<HTMLSelectElement>("Because"), "component_not_present");
    change(field<HTMLSelectElement>("It would say"), "deferred");
    change(field<HTMLInputElement>("For how long"), days);
    change(field<HTMLTextAreaElement>("In these words"), " Waiting on the vendor. ");
  }

  it("sends a deferral's length and drops the reason an earlier outcome chose", async () => {
    const sent = preparing();
    await prepared("90");
    await press(mount.host(), "Save");
    await settle();
    expect(only(sent)[1].body).toEqual({
      query: "exploited=1",
      prepares: { outcome: "deferred", reasoning: "Waiting on the vendor.", defer_days: 90 },
    });
  });

  it("sends no length beside an outcome other than a deferral", async () => {
    const sent = preparing();
    await prepared("90");
    change(field<HTMLSelectElement>("It would say"), "not-applicable");
    change(field<HTMLSelectElement>("Because"), "component_not_present");
    await press(mount.host(), "Save");
    await settle();
    expect(only(sent)[1].body).toEqual({
      query: "exploited=1",
      prepares: {
        outcome: "not-applicable",
        justification: "component_not_present",
        reasoning: "Waiting on the vendor.",
      },
    });
  });

  it("saves no deferral of part of a day", async () => {
    preparing();
    await prepared("1.5");
    expect(button("Save")?.disabled).toBe(true);
    change(field<HTMLInputElement>("For how long"), "2");
    expect(button("Save")?.disabled).toBe(false);
  });
});
