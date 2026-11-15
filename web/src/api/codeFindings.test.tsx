// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import {
  codeFindingTrendRead,
  useApproveSuppressionRule,
  useAssignCodeFinding,
  useCodeFindings,
  useDecideCodeFinding,
  useFixCodeFinding,
  useIncludeCodeFinding,
  useProposeSuppressionRule,
  useRecordAsFlaw,
  useRetireSuppressionRule,
  useUndoRecordAsFlaw,
} from "./codeFindings";
import { acted } from "../test/acted";
import { EVERY_DECISION_KEY } from "../test/decisionKeys";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

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

// A code finding or a rule moves every decision read and the rules, whose
// coverage follows either. A key dropped from one of these sets leaves a
// screen showing what the act changed as it stood before.
const AFTER_CODE_FINDING = [...EVERY_DECISION_KEY, "suppression-rules"].sort();

// Recording as a flaw also moves the flaw offered and the findings lists the
// flaw now sits on.
const AFTER_FLAW = [...AFTER_CODE_FINDING, "code-finding-flaw"].sort();

describe("an act on a code finding or a rule, once it lands", () => {
  it.each([
    [
      "deciding",
      "POST",
      () => useDecideCodeFinding(build, "o1"),
      { state: "false-positive", because: "x" },
    ],
    ["fixing", "POST", () => useFixCodeFinding(build, "o1"), { because: "x", fixedIn: 3 }],
    ["proposing a rule", "POST", () => useProposeSuppressionRule("sonic"), { reasoning: "x" }],
    ["approving a rule", "POST", () => useApproveSuppressionRule("sonic"), 4],
    ["retiring a rule", "DELETE", () => useRetireSuppressionRule("sonic"), 4],
  ] as const)("%s moves every decision read and the rules", async (_, method, hook, vars) => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      method,
      hook as never,
      vars as never,
    );
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual(AFTER_CODE_FINDING);
  });

  it.each([
    ["recording as a flaw", "POST", () => useRecordAsFlaw(build, "o1"), { reasoning: "x" }],
    ["withdrawing the flaw", "POST", () => useUndoRecordAsFlaw(build, "o1"), "x"],
    ["including in disclosure", "PUT", () => useIncludeCodeFinding(build, "o1"), true],
    ["leaving out of disclosure", "DELETE", () => useIncludeCodeFinding(build, "o1"), false],
  ] as const)("%s moves the flaw offered as well", async (_, method, hook, vars) => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      method,
      hook as never,
      vars as never,
    );
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual(AFTER_FLAW);
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
