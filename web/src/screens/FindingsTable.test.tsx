// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { FindingsTable, type Decided } from "./FindingsTable";
import { identityOf, type Row } from "./list";
import { mounted, screen, settle } from "../test/mount";

const mount = mounted();

const row = (issue: string) =>
  ({
    product: "sonic",
    vulnerability: issue,
    fold: `libfoo ${issue}`,
    component: "libfoo",
    version: "1.2.3",
    state: "waiting",
  }) as unknown as Row;

async function draw(rows: Row[], decided: Decided) {
  mount.render(
    screen(
      <FindingsTable
        rows={rows}
        shownKeys={rows.map(identityOf)}
        picked={new Map()}
        pick={() => {}}
        pickAll={() => {}}
        spanning={false}
        oneBuild
        sortable={(label) => label}
        buildOf={() => ({ product: "sonic", stream: "master", variant: "broadcom" })}
        siblings={new Map()}
        carrying=""
        prepared={null}
        set={() => {}}
        hide={() => {}}
        peeking={null}
        setPeeking={() => {}}
        onDecided={() => {}}
        cursor={-1}
        decided={decided}
        onDismiss={() => {}}
      />,
    ),
  );
  await settle();
}

// A decision that waits, recorded from the preview of the row named.
const decided = (key: string, next: string | null): Decided => ({
  key,
  next,
  issue: "CVE-2026-1",
  recorded: {
    claimId: 7,
    recorded: 1,
    covered: 1,
    left: 0,
    needsApproval: true,
    applied: [],
    matching: 0,
    outcome: "not-applicable",
  },
});

describe("the confirmation of a decision taken from a row's preview", () => {
  // Verified by removing the fallback after the rows: the confirmation and
  // its link go with it and this fails.
  it("stays on the page when the decided row was the last and has left the list", async () => {
    const left = row("CVE-2026-1");
    await draw([row("CVE-2026-2")], decided(identityOf(left), null));
    const links = Array.from(mount.host().querySelectorAll("a")).map((each) => each.textContent);
    expect(links).toContain("Open the decision →");
  });

  it("is drawn once, in the decided row's place, when the row after it is listed", async () => {
    const left = row("CVE-2026-1");
    const next = row("CVE-2026-2");
    await draw([next], decided(identityOf(left), identityOf(next)));
    expect(mount.host().querySelectorAll('[role="status"]').length).toBe(1);
  });
});
