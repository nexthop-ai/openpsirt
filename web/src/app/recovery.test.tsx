// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Boundary } from "./Boundary";
import { retrying } from "./retrying";
import { mounted, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("a screen whose chunk failed to arrive", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("is asked for again when Try again is pressed", async () => {
    let calls = 0;
    const Screen = retrying(async () => {
      calls++;
      if (calls === 1) throw new Error("the chunk did not arrive");
      return function Arrived() {
        return <p>arrived</p>;
      };
    });
    mount.render(
      <Boundary>
        <Suspense fallback={<p>loading</p>}>
          <Screen />
        </Suspense>
      </Boundary>,
    );
    await settle();
    expect(mount.host().textContent).toContain("This screen could not be drawn.");
    const again = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Try again",
    );
    act(() => again?.click());
    await settle();
    expect(mount.host().textContent).toContain("arrived");
    expect(calls).toBe(2);
  });
});

describe("the identity read", () => {
  // Each test reads its own copy of the session modules, so a session one
  // test ended is not ended in the next. The answering spy is installed on
  // the same copy of the client those modules call.
  let fresh: {
    useWho: typeof import("./session").useWho;
    snapshot: typeof import("./ended").snapshot;
    serve: typeof serve;
  };
  beforeEach(async () => {
    vi.resetModules();
    const [session, ended, test] = await Promise.all([
      import("./session"),
      import("./ended"),
      import("../test/mount"),
    ]);
    fresh = { useWho: session.useWho, snapshot: ended.snapshot, serve: test.serve };
  });

  function Name() {
    const who = fresh.useWho();
    return <p>{who.data ? who.data.identity : who.isPending ? "…" : "nobody"}</p>;
  }

  it("keeps the identity it held when the session ends under it, and says so", async () => {
    let signedIn = true;
    fresh.serve((path) =>
      path === "/v1/session/me"
        ? signedIn
          ? { data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] } }
          : { status: 401 }
        : undefined,
    );
    const queries = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    mount.render(
      <QueryClientProvider client={queries}>
        <Name />
      </QueryClientProvider>,
    );
    await settle();
    expect(mount.host().textContent).toBe("ana");
    signedIn = false;
    await act(() => queries.invalidateQueries({ queryKey: ["whoami"] }));
    await settle();
    expect(mount.host().textContent).toBe("ana");
    expect(fresh.snapshot()).toBe(true);
  });

  it("says nobody is signed in where nobody was", async () => {
    fresh.serve((path) => (path === "/v1/session/me" ? { status: 401 } : undefined));
    const queries = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    mount.render(
      <QueryClientProvider client={queries}>
        <Name />
      </QueryClientProvider>,
    );
    await settle();
    expect(mount.host().textContent).toBe("nobody");
    expect(fresh.snapshot()).toBe(false);
  });
});
