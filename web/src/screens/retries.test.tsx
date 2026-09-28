// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { Findings } from "./Findings";
import { IssueAdvisory } from "./IssueAdvisory";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ok = (data: unknown, status = 200) => ({
  data,
  error: undefined,
  response: new Response(null, { status }),
});

describe("starting an advisory", () => {
  it("mints one name and adds the flaw once, however many attempts it takes", async () => {
    let reads = 0;
    serve((path) => {
      if (path === "/v1/advisories/{advisory}/document") {
        reads++;
        return reads === 1 ? { status: 503 } : { data: { document: {} } };
      }
      return { data: { items: [], total: 0 } };
    });
    const posts: string[] = [];
    vi.spyOn(api, "POST").mockImplementation((async (path: string) => {
      posts.push(path);
      return path === "/v1/advisories" ? ok({ advisory: "EXNET-2026-0001" }, 201) : ok({}, 201);
    }) as never);

    mount.render(
      screen(
        <IssueAdvisory
          vulnerability="CVE-2026-1"
          recorded
          products={[{ name: "sonic", called: "SONiC" }]}
        />,
      ),
    );
    await settle();
    const start = () =>
      Array.from(mount.host().querySelectorAll("button")).find(
        (each) => each.textContent === "Start an advisory",
      );
    act(() => start()?.click());
    await settle();
    act(() => start()?.click());
    await settle();
    expect(reads).toBe(2);
    expect(posts).toEqual(["/v1/advisories", "/v1/advisories/{advisory}/issues"]);
  });
});

describe("the findings search box", () => {
  it("empties when the term leaves the address", async () => {
    serve((path) =>
      path === "/v1/session/me"
        ? { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] } }
        : { data: { items: [], total: 0 } },
    );
    mount.render(screen(<Findings />, "/findings?q=openssl", "/findings"));
    await settle();
    const box = () => mount.host().querySelector<HTMLInputElement>(".searchbox input");
    expect(box()?.value).toBe("openssl");
    const clear = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.includes("Clear all"),
    );
    const chip = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.includes("openssl"),
    );
    act(() => (clear ?? chip)?.click());
    await settle();
    expect(box()?.value).toBe("");
  });
});
