// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AutoAssignment } from "./AutoAssignment";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { button, change, only, press, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const RULES = [
  { id: 3, order: 1, name: "kernel", team: "platform", upstream: "linux", beneath: "sonic" },
  { order: 2, name: "half answered", team: "gone", team_retired: true, beneath: "x" },
];

async function drawn(
  caught: (query: Record<string, unknown>) => number,
  at = "/auto-assignment?product=sonic",
) {
  serve((path, init) => {
    const query = (init as Init).params?.query ?? {};
    if (path === "/v1/products") return { data: { items: [{ name: "sonic" }] } };
    if (path === "/v1/teams") return { data: { items: [{ name: "platform" }] } };
    if (path === "/v1/products/{product}/routing-rules") return { data: { items: RULES } };
    if (path === "/v1/products/{product}/findings/components")
      return {
        data: {
          items: [
            { component: "linux-image-6.12", source_package: "linux" },
            { component: "busybox", source_package: "" },
          ],
        },
      };
    if (path === "/v1/products/{product}/routing-rules/preview") {
      const total = caught(query);
      return { data: { total, components: total ? ["linux-image-6.12"] : [], unheld: 4, work: 9 } };
    }
    return undefined;
  });
  const writes = {
    post: answer("POST", () => ({ data: {} })),
    del: answer("DELETE", () => ({ data: {} })),
  };
  mount.render(screen(<AutoAssignment />, at));
  await settle();
  return writes;
}

const field = (selector: string) => mount.host().querySelector<HTMLInputElement>(selector);
const text = () => mount.host().textContent ?? "";

async function fill(upstream: string) {
  change(field('input[placeholder="kernel to the platform team"]'), "kernel rule");
  change(
    Array.from(mount.host().querySelectorAll<HTMLSelectElement>("select")).find((each) =>
      each.textContent?.includes("Pick a team"),
    ) ?? null,
    "platform",
  );
  change(field("#rule-upstream"), upstream);
  await settle();
}

describe("the rules that route work to a team", () => {
  it("adds a rule naming only the key that was given", async () => {
    const { post } = await drawn(() => 2);
    await fill(" linux* ");
    expect(text()).toContain("Catches 2 components");
    expect(text()).toContain("Would place 4 of 9 unheld");
    await press(mount.host(), "Add");
    await settle();
    const [, init] = only(post);
    expect(init.params?.path).toEqual({ product: "sonic" });
    expect(init.body).toEqual({ name: "kernel rule", team: "platform", upstream: "linux*" });
    expect(text()).toContain("Recorded.");
  });

  it("holds back a rule that catches nothing, and offers the package it was cut from", async () => {
    await drawn((query) => (query.upstream === "linux" ? 3 : 0));
    await fill("linux-image-6.12");
    expect(text()).toContain("Nothing is called that.");
    expect(button(mount.host(), "Add").disabled).toBe(true);
    await press(mount.host(), "linux");
    await settle();
    expect(field("#rule-upstream")?.value).toBe("linux");
    expect(button(mount.host(), "Add").disabled).toBe(false);
  });

  it("retires the rule named, and not one the server did not identify", async () => {
    const { del } = await drawn(() => 0);
    const retire = Array.from(mount.host().querySelectorAll("button")).filter(
      (each) => each.textContent === "Retire",
    );
    expect(retire[1]?.disabled).toBe(true);
    await act(async () => retire[0]?.click());
    await settle();
    expect(only(del)[1].params?.path).toEqual({ product: "sonic", id: 3 });
    expect(text()).toContain("What it placed stays assigned.");
    expect(text()).toContain("· retired");
  });

  it("asks for a product before anything else", async () => {
    await drawn(() => 0, "/auto-assignment");
    expect(text()).toContain("Pick a product.");
  });
});
