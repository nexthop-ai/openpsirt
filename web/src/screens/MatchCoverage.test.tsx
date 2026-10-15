// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { MatchCoverage } from "./MatchCoverage";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { press, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ROUTE = "/v1/products/{product}/streams/{stream}/variants/{variant}/match-coverage";

async function drawn(total = 2, at = "/products/sonic/streams/master/variants/arm/match-coverage") {
  const spy = serve((path) =>
    path === ROUTE
      ? {
          data: {
            unmatched: total,
            components: 40,
            total,
            reasons: [
              { reason: "no-version", count: total },
              { reason: "no-identifier", count: 0 },
            ],
            items: [
              { name: "busybox", version: "", reason: "no-version", purl: "pkg:generic/busybox" },
            ],
          },
        }
      : undefined,
  );
  mount.render(
    screen(
      <MatchCoverage />,
      at,
      "/products/:product/streams/:stream/variants/:variant/match-coverage",
    ),
  );
  await settle();
  return () =>
    (spy.mock.calls as unknown as [string, Init][])
      .filter(([path]) => path === ROUTE)
      .map(([, init]) => init.params?.query ?? {});
}

describe("the components a scanner cannot match", () => {
  it("narrows to one reason, from the first page, and the file follows", async () => {
    const asked = await drawn(450);
    await press(mount.host(), "Next");
    await settle();
    expect(asked().at(-1)?.offset).toBe(200);
    await press(mount.host(), "No version 450");
    await settle();
    expect(asked().at(-1)).toEqual({ reason: "no-version", limit: 200, offset: 0 });
    expect(location()).toContain("reason=no-version");
    const csv = Array.from(mount.host().querySelectorAll("a")).find((a) => a.textContent === "CSV");
    expect(csv?.getAttribute("href")).toContain("reason=no-version");
  });

  it("offers no reason nothing falls under", async () => {
    await drawn();
    expect(mount.host().textContent).not.toContain("No package identifier");
    expect(mount.host().textContent).toContain("pkg:generic/busybox");
  });

  it("says every component can be matched", async () => {
    await drawn(0);
    expect(mount.host().textContent).toContain(
      "The scanner can match every component in this build.",
    );
  });
});
