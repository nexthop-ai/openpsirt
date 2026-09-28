// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useEffect, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, vi } from "vitest";
import { api } from "../api/client";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

// A component drawn into a detached host, through React's own act.
//
// Installs its own beforeEach and afterEach, so a test file calls it once at
// the top level and reads the host inside each test.
export function mounted(): {
  host: () => HTMLDivElement;
  render: (node: ReactNode) => void;
} {
  let host: HTMLDivElement | undefined;
  let root: Root | undefined;

  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
  });

  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
  });

  return {
    host: () => {
      if (!host) throw new Error("the host exists only inside a test");
      return host;
    },
    render: (node) => act(() => root?.render(node)),
  };
}

// One answer the fake server gives: a body, or a status with no body.
export type Answer = { data?: unknown; status?: number };

type Served = (path: string, init: unknown) => Answer | undefined;

// The generated client's GET, answering from a function of the path it was
// asked for and the parameters it was asked with.
//
// A path the function does not answer is a 500, so a test that forgets a
// read sees the screen's failure branch rather than a hang.
export function serve(answer: Served) {
  return vi.spyOn(api, "GET").mockImplementation(answering(answer));
}

// One request a screen sent: the path and what it was sent with.
export type Sent = [path: string, init: unknown];

// The generated client's POST, answered the same way. What it returns reads
// back every request sent so far, in order.
export function accept(answer: Served): () => Sent[] {
  const spy = vi.spyOn(api, "POST").mockImplementation(answering(answer));
  return () => spy.mock.calls as unknown as Sent[];
}

function answering(answer: Served) {
  return (async (path: string, init: unknown) => {
    const said = answer(path, init) ?? { status: 500 };
    const status = said.status ?? 200;
    const ok = status >= 200 && status < 300;
    return {
      data: ok ? said.data : undefined,
      error: ok ? undefined : { detail: `HTTP ${status}` },
      response: new Response(null, { status }),
    };
  }) as never;
}

// Where the router is, after whatever the test pressed.
const seen = { at: "" };

function Here() {
  const at = useLocation();
  useEffect(() => {
    seen.at = at.pathname + at.search;
  });
  return null;
}

export function location(): string {
  return seen.at;
}

// A query client with no retries, so a failed read settles at once.
export function client(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

// The query keys a client is asked to invalidate from here on, each joined
// with "/" and sorted, so a test compares the set an act invalidates.
export function watchInvalidations(queries: QueryClient): () => string[] {
  const spy = vi.spyOn(queries, "invalidateQueries");
  return () =>
    spy.mock.calls
      .map(([filters]) => ((filters as { queryKey?: unknown[] })?.queryKey ?? []).join("/"))
      .sort();
}

// A screen inside a router and a query client of its own, at an address.
//
// A fresh client per draw, so nothing one test cached is read by the next. A
// test that watches what a screen invalidates passes the client it watches.
export function screen(
  node: ReactNode,
  at = "/",
  pattern = "*",
  queries: QueryClient = client(),
): ReactNode {
  return (
    <QueryClientProvider client={queries}>
      <MemoryRouter initialEntries={[at]}>
        <Here />
        <Routes>
          <Route path={pattern} element={node} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// Lets every pending read and render finish.
export async function settle(): Promise<void> {
  for (let round = 0; round < 5; round++) {
    await act(async () => {
      await new Promise((done) => setTimeout(done, 0));
    });
  }
}
