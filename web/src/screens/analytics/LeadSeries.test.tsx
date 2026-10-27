// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LeadSeries } from "./LeadSeries";
import { mounted, screen, serve, settle } from "../../test/mount";

const mount = mounted();

beforeEach(() => window.sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

const COUNTS = "/v1/products/{product}/code-finding-series";

async function drawn(readsInternal: boolean) {
  window.sessionStorage.setItem("openpsirt.scope", JSON.stringify({ product: "sonic" }));
  const spy = serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [{ product: "sonic", reads_internal: readsInternal }],
          outcomes: [],
        },
      };
    if (path === COUNTS)
      return {
        data: {
          items: [
            {
              series: "semgrep/default",
              states: { open: 3, "not-reproduced": 40, dismissed: 2 },
              waiting: 1,
              ruled: 2,
            },
          ],
        },
      };
    return undefined;
  });
  mount.render(screen(<LeadSeries />, "/analytics/leads-by-analyzer"));
  await settle();
  return spy;
}

const text = () => mount.host().textContent ?? "";

describe("leads by analyzer", () => {
  it("asks for no count where the reader does not read internal material in the product", async () => {
    const spy = await drawn(false);
    const paths = (spy.mock.calls as unknown as [string][]).map(([path]) => path);
    expect(paths).toContain("/v1/session/me");
    expect(paths).not.toContain(COUNTS);
    expect(text()).toContain("Leads are internal.");
  });

  it("opens each figure on the list of that series in that state", async () => {
    await drawn(true);
    const open = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.getAttribute("title") === "1 waiting for approval",
    );
    expect(open?.textContent).toBe("3");
    const asked = new URL(open?.getAttribute("href") ?? "", "http://x");
    expect(asked.pathname).toBe("/products/sonic/leads");
    expect(asked.searchParams.get("series")).toBe("semgrep/default");
    expect(asked.searchParams.get("state")).toBe("open");
  });
});
