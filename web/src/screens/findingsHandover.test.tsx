// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { useHandOver } from "./findingsHandover";
import { listQuery, type Row } from "./list";
import { mounted, screen, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("handing rows over", () => {
  let seen: ReturnType<typeof useHandOver> | undefined;
  function HandOver() {
    seen = useHandOver({
      product: "sonic",
      query: listQuery(new URLSearchParams("state=undecided&offset=50&page=50")),
      selection: { stream: "main" },
      buildOf: (row: Row) => ({ product: "sonic", stream: row.stream ?? "", variant: "x86" }),
    });
    return null;
  }

  it("hands every matching row over with the list's filter and no page", async () => {
    const sent = vi
      .spyOn(api, "POST")
      .mockResolvedValue({ data: { assigned: 3 }, response: new Response() } as never);
    mount.render(screen(<HandOver />));
    await settle();
    await act(async () => {
      await seen?.handMatching.mutateAsync({
        who: "ana",
        team: false,
        only: [{ vulnerability: "CVE-2026-0001", fold: "zlib" } as Row],
      });
    });
    const init = sent.mock.calls[0]?.[1] as unknown as {
      params: { query: Record<string, unknown> };
      body: Record<string, unknown>;
    };
    expect(init.params.query).toMatchObject({ state: ["undecided"], stream: "main" });
    expect(init.params.query).not.toHaveProperty("offset");
    expect(init.params.query).not.toHaveProperty("limit");
    expect(init.body).toEqual({
      person: "ana",
      only: [{ vulnerability: "CVE-2026-0001", fold: "zlib" }],
    });
  });

  it("hands one row over at the build it names", async () => {
    const sent = vi
      .spyOn(api, "PUT")
      .mockResolvedValue({ data: {}, response: new Response() } as never);
    mount.render(screen(<HandOver />));
    await settle();
    await act(async () => {
      await seen?.hand.mutateAsync({
        row: { vulnerability: "CVE-2026-0001", component: "zlib", stream: "rel" } as Row,
        who: "core",
        team: true,
      });
    });
    const init = sent.mock.calls[0]?.[1] as unknown as {
      params: { path: Record<string, string> };
      body: Record<string, unknown>;
    };
    expect(init.params.path).toEqual({
      product: "sonic",
      stream: "rel",
      variant: "x86",
      vulnerability: "CVE-2026-0001",
      component: "zlib",
    });
    expect(init.body).toEqual({ team: "core" });
  });
});
