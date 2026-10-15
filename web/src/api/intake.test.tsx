// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  useAcceptReport,
  useAcknowledgeReport,
  useApproveRuling,
  useRecordReport,
  useRule,
  useWithdrawRuling,
} from "./intake";
import { acted } from "../test/acted";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// Everything a change to a report or a ruling moves.
const EVERY_REPORT_KEY = [
  "disclosing",
  "duplicate-disclosure",
  "duplicates",
  "finding",
  "findings",
  "home",
  "issue",
  "recorded-report",
  "report",
  "reports",
  "rulings",
].sort();

describe("an act on a report, once it lands", () => {
  it.each([
    ["filing one", "POST", () => useRecordReport("sonic"), { summary: "A socket answers." }],
    ["acknowledging one", "POST", () => useAcknowledgeReport("sonic", "R-1"), undefined],
    ["accepting one as an issue", "PUT", () => useAcceptReport("sonic", "R-1"), "CVE-2026-1"],
    ["proposing a ruling", "POST", () => useRule("sonic"), { reports: ["R-1"], outcome: "spam" }],
    ["approving a ruling", "POST", () => useApproveRuling("sonic"), 4],
    ["withdrawing a ruling", "POST", () => useWithdrawRuling("sonic"), 4],
  ] as const)("%s moves every report read", async (_, method, useHook, vars) => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      method,
      useHook as () => { mutate: (vars: unknown) => void },
      vars,
    );
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual(EVERY_REPORT_KEY);
  });

  it("accepting a report names the issue it becomes", async () => {
    const { sent } = await acted(
      mount.render,
      mount.host,
      "PUT",
      () => useAcceptReport("sonic", "R-1"),
      "CVE-2026-1",
    );
    expect(sent).toEqual([
      [
        "/v1/products/{product}/reports/{reference}/issue",
        {
          params: { path: { product: "sonic", reference: "R-1" } },
          body: { vulnerability: "CVE-2026-1" },
        },
      ],
    ]);
  });
});
