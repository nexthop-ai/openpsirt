// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import { Home } from "./Home";
import { Shell } from "../app/Shell";
import { remember } from "../app/scope";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

const who = {
  identity: "ana",
  name: "Ana",
  admin: false,
  kind: "person" as const,
  reach: [],
  outcomes: [],
};

// Every count of the whole review queue Home and the rail around it sent.
async function wholeQueueCounts(): Promise<number> {
  const asked = serve(() => ({ data: { items: [], total: 0 } }));
  mount.render(
    screen(
      <Shell who={who}>
        <Home who={who} />
      </Shell>,
    ),
  );
  await settle();
  const sent = asked.mock.calls as unknown as [path: string, init: unknown][];
  return sent.filter(([path, init]) => {
    const query = (init as { params?: { query?: Record<string, unknown> } })?.params?.query ?? {};
    return path === "/v1/review-queue" && query.limit === 0 && !query.product && !query.reason;
  }).length;
}

describe("the review queue's count on Home", () => {
  afterEach(() => window.sessionStorage.clear());

  it("is asked once for the rail and Home together with nothing picked", async () => {
    expect(await wholeQueueCounts()).toBe(1);
  });

  it("is asked once for the rail, the figures and the panel with a product picked", async () => {
    remember({ product: "sonic", stream: "master", variant: "broadcom" });
    expect(await wholeQueueCounts()).toBe(1);
  });
});
