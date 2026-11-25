// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from "vitest";
import { Card, Dated } from "./QueueCard";
import { decisionOf } from "../api/decisions";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { button, change, only, press } from "../test/controls";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());

// A promise whose date passed with the finding open, as the queue lists one.
function missed(outcome: string, upgradeTo = "") {
  return decisionOf({
    age_days: 3,
    builds: ["master · broadcom"],
    decision: { id: 7, kind: "finding", proposed_at: "2026-09-01T00:00:00Z", proposed_by: "bo" },
    decision_occurrence: {
      id: 70,
      outcome,
      reasoning: "the vendor ships it next month",
      committed_to: "2026-10-01",
      upgrade_to: upgradeTo,
    },
    rows: 1,
    issues: 1,
    occurrences: 1,
    occurrence: { occurrence: "p7", product: "sonic", vulnerability: "CVE-2026-7" },
    proposed_by: "bo",
    reasoning: "the vendor ships it next month",
  } as never);
}

async function repromised(outcome: string, upgradeTo = "", version?: string) {
  serve(() => ({ data: { items: [], total: 0 } }));
  const sent = answer("PUT", () => ({ data: {} }));
  mount.render(
    screen(<Dated decision={missed(outcome, upgradeTo)} reason="missed-fix-date" marked={false} />),
  );
  await settle();
  const opener = outcome === "upgrade-needed" ? "Change the version or date" : "Change the date";
  await press(mount.host(), opener);
  if (version !== undefined) {
    change(mount.host().querySelector<HTMLInputElement>('input[type="text"]'), version);
  }
  change(mount.host().querySelector<HTMLInputElement>('input[type="date"]'), "2026-12-01");
  change(mount.host().querySelector("textarea"), "The vendor slipped a month.");
  return sent;
}

describe("changing a missed promise", () => {
  it("sends the version beside the date for an upgrade", async () => {
    const sent = await repromised("upgrade-needed", "3.0.15", " 3.0.16 ");
    await press(mount.host(), "Change the promise");
    await settle();
    const [path, init] = only(sent);
    expect(path).toBe("/v1/decisions/{id}/promise");
    expect(init.params?.path).toEqual({ id: 7 });
    expect(init.body).toEqual({
      to: "3.0.16",
      by: "2026-12-01",
      reasoning: "The vendor slipped a month.",
    });
    expect(mount.host().textContent).toContain("Promise changed");
  });

  it("sends no version for a promise that names none", async () => {
    const sent = await repromised("patch-needed");
    await press(mount.host(), "Change the promise");
    await settle();
    expect(only(sent)[1].body).toEqual({
      by: "2026-12-01",
      reasoning: "The vendor slipped a month.",
    });
  });

  it("holds an upgrade with its version cleared", async () => {
    await repromised("upgrade-needed", "3.0.15", "  ");
    expect(button(mount.host(), "Change the promise").disabled).toBe(true);
  });
});

describe("a correction by source paths waiting", () => {
  it("shows the rule and its reach as a bulk act does", async () => {
    serve(() => ({ data: { items: [], total: 0 } }));
    const decision = decisionOf({
      age_days: 0,
      builds: ["master · broadcom"],
      decision: { id: 9, kind: "source", proposed_at: "2026-11-18T00:00:00Z", proposed_by: "bo" },
      decision_occurrence: { id: 90, outcome: "mismatched", reasoning: "Built from tools/." },
      rows: 40,
      issues: 40,
      occurrences: 40,
      occurrence: { occurrence: "p9", product: "sonic", vulnerability: "CVE-2024-26600" },
      proposed_by: "bo",
      reasoning: "Built from tools/.",
      source: { package: "linux-perf", source: "linux", paths: ["tools/lib", "tools/perf"] },
    } as never);
    mount.render(
      screen(<Card decision={decision} marked={false} picked={false} onPick={() => {}} />),
    );
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("By source paths");
    expect(text).toContain("linux-perf built from tools/lib, tools/perf of linux");
    expect(text).toContain("40 issues now, and new ones as scans find them");
    expect(text).not.toContain("one decision in this build");
    expect(text).not.toContain("each expiring independently");
    expect(text).not.toContain("read once and approved once");
    expect(button(mount.host(), "Approve the rule")).not.toBeNull();
    expect(button(mount.host(), "Reject the rule")).not.toBeNull();
  });

  it("is titled by the rule and opens it, not the issue it is stored against", async () => {
    serve(() => ({ data: { items: [], total: 0 } }));
    const decision = decisionOf({
      age_days: 0,
      builds: ["master · broadcom"],
      decision: { id: 9, kind: "source", proposed_at: "2026-11-18T00:00:00Z", proposed_by: "bo" },
      decision_occurrence: { id: 90, outcome: "mismatched", reasoning: "Built from tools/." },
      rows: 40,
      issues: 40,
      occurrences: 40,
      occurrence: { occurrence: "p9", product: "sonic", vulnerability: "CVE-2024-26600" },
      finding: {
        product: "sonic",
        branch_or_tag: "master",
        variant: "broadcom",
        vulnerability: "CVE-2024-26600",
        component: "linux-perf",
        severity: "critical",
      },
      counter: { elsewhere: { affected: 3 } },
      proposed_by: "bo",
      reasoning: "Built from tools/.",
      source: { package: "linux-perf", source: "linux", paths: ["tools/lib", "tools/perf"] },
    } as never);
    mount.render(
      screen(<Card decision={decision} marked={false} picked={false} onPick={() => {}} />),
    );
    await settle();
    const title = mount.host().querySelector("header a.id");
    expect(title?.textContent).toBe("linux-perf through linux");
    expect(title?.getAttribute("href")).toBe("/decisions/9");
    expect(mount.host().textContent).not.toContain("CVE-2024-26600");
    expect(mount.host().textContent).not.toContain("Before approving");
  });
});
