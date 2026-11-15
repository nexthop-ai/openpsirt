// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { codeFindingTrendRead, useCodeFindings, useAssignCodeFinding } from "./codeFindings";
import { acted } from "../test/acted";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const build = { product: "sonic", branch_or_tag: "master", variant: "broadcom" };

describe("a code finding handed to a holder, once it lands", () => {
  it("moves the holdings and every list of who holds what", async () => {
    const { invalidated } = await acted(
      mount.render,
      mount.host,
      "PUT",
      () => useAssignCodeFinding(build, "abc"),
      { kind: "team" as const, identity: "kernel" },
    );
    expect(invalidated).toEqual(expect.arrayContaining(["assigned", "holdings", "team-assigned"]));
  });
});

const NARROWING = {
  branch_or_tag: "master",
  variant: "broadcom",
  series: "semgrep/default",
  method: "sast" as const,
  state: "open" as const,
  assigned: "nobody" as const,
  component: "frr",
  component_version: "10.2",
  beneath: "frr",
  beneath_version: "10.2",
  beneath_ecosystem: "deb",
  beneath_namespace: "debian",
};

async function sentFor(product: string, asked: typeof NARROWING & { offset?: number }) {
  const sent: unknown[] = [];
  serve((_path, init) => {
    sent.push((init as { params: { query: unknown } }).params.query);
    return { data: { items: [], total: 0 } };
  });
  function Read() {
    useCodeFindings(product, asked);
    return null;
  }
  mount.render(screen(<Read />));
  await settle();
  return sent[0];
}

describe("a request for code findings", () => {
  it("sends every narrowing a product's list is asked with, and nothing unset", async () => {
    expect(await sentFor("sonic", { ...NARROWING, offset: 50, component: "" })).toEqual({
      limit: 50,
      offset: 50,
      ...NARROWING,
      component: undefined,
    });
  });

  it("sends across products only the narrowings that name no build", async () => {
    expect(await sentFor("", NARROWING)).toEqual({
      limit: 50,
      offset: 0,
      series: "semgrep/default",
      method: "sast",
      state: "open",
      assigned: "nobody",
      component: "frr",
      component_version: "10.2",
    });
  });

  it("sends the trend every narrowing it is asked with, and the one window it names", async () => {
    const sent: unknown[] = [];
    serve((_path, init) => {
      sent.push((init as { params: { query: unknown } }).params.query);
      return { data: {} };
    });
    const trend = { ...NARROWING, state: undefined, assigned: undefined };
    await new QueryClient().fetchQuery(codeFindingTrendRead("sonic", { ...trend, weeks: 26 }));
    expect(sent[0]).toEqual({ ...trend, weeks: 26 });
  });
});
