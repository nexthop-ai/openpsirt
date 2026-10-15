// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  useAgree,
  useMarkRelease,
  useNameAFlaw,
  useRecordIssued,
  useRetitle,
  useTakeAFlawOff,
  useTakeAgreementBack,
} from "./advisories";
import { acted } from "../test/acted";
import { mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// Everything a change to an advisory moves.
const EVERY_ADVISORY_KEY = [
  "advisories",
  "advisory",
  "advisory-document",
  "advisory-issuances",
  "advisory-releases",
].sort();

const advisory = "SONIC-2026-1";
const flaw = { advisory, product: "sonic", vulnerability: "CVE-2026-1" };

describe("an act on an advisory, once it lands", () => {
  it.each([
    ["retitling", "PATCH", useRetitle, { advisory, title: "Two flaws in the socket" }],
    ["naming a flaw", "POST", useNameAFlaw, flaw],
    ["taking a flaw off", "DELETE", useTakeAFlawOff, flaw],
    ["agreeing", "POST", useAgree, { advisory }],
    ["taking agreement back", "DELETE", useTakeAgreementBack, { advisory }],
    ["recording it issued", "POST", useRecordIssued, { advisory, summary: "" }],
    [
      "marking a release",
      "PUT",
      useMarkRelease,
      { ...flaw, stream: "master", variant: "broadcom", affected: true },
    ],
  ] as const)("%s moves every advisory read", async (_, method, useHook, vars) => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      method,
      useHook as () => { mutate: (vars: unknown) => void },
      vars,
    );
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual(EVERY_ADVISORY_KEY);
  });

  it("names the flaw in the body and the advisory in the path", async () => {
    const { sent } = await acted(mount.render, mount.host, "POST", useNameAFlaw, flaw);
    expect(sent).toEqual([
      [
        "/v1/advisories/{advisory}/issues",
        {
          params: { path: { advisory } },
          body: { product: "sonic", vulnerability: "CVE-2026-1" },
        },
      ],
    ]);
  });

  it("marks a release without sending the advisory twice", async () => {
    const { sent } = await acted(mount.render, mount.host, "PUT", useMarkRelease, {
      ...flaw,
      stream: "master",
      variant: "broadcom",
      affected: false,
    });
    expect(sent[0]?.[1]).toEqual({
      params: { path: { advisory } },
      body: {
        product: "sonic",
        vulnerability: "CVE-2026-1",
        stream: "master",
        variant: "broadcom",
        affected: false,
      },
    });
  });

  it("moves nothing when the act is refused", async () => {
    const { invalidated } = await acted(
      mount.render,
      mount.host,
      "POST",
      useAgree,
      { advisory },
      422,
    );
    expect(invalidated).toEqual([]);
  });
});
