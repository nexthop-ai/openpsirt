// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { CodeFindings } from "./CodeFindings";
import { client, location, mounted, screen, serve, settle } from "../test/mount";
import { change, press, tick } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ROW = {
  occurrence: "abc",
  rule: "clang/unix.Malloc",
  path: "src/a.c",
  line: 7,
  message: "p is leaked",
  branch_or_tag: "master",
  variant: "broadcom",
  builds: 3,
  component: "frr",
  version: "10.2",
  opened: "2026-10-01",
  state: "open",
  assigned_to: "kernel",
  assigned_to_name: "Kernel",
  assigned_team: true,
};
const ROWS = [ROW];

async function drawn(at = "/products/sonic/code-findings", rows: object[] = ROWS) {
  const asked: unknown[] = [];
  serve((path, init) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          kind: "person",
          reach: [{ product: "sonic", reads_security_testing: true }],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/code-findings") {
      asked.push((init as { params: { query: unknown } }).params.query);
      return {
        data: {
          items: rows,
          total: 1,
          states: { "no-longer-detected": 40, open: 1 },
          waiting: 2,
          ruled: 5,
          past_end_of_life: 3,
        },
      };
    }
    return undefined;
  });
  mount.render(screen(<CodeFindings />, at, "/products/:product/code-findings"));
  await settle();
  return asked;
}

const text = () => mount.host().textContent ?? "";

describe("the code findings", () => {
  it("links each row's component, and names the whole build where it is on no component", async () => {
    await drawn("/products/sonic/code-findings", [
      ROW,
      { ...ROW, occurrence: "def", component: "sonic", version: "", on_build: true },
    ]);
    const link = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "frr 10.2",
    );
    expect(link?.getAttribute("href")).toBe(
      "/products/sonic/components/frr?branch_or_tag=master&variant=broadcom",
    );
    expect(text()).toContain("Whole build");
  });

  it("offers the list as a file asked with the same narrowing", async () => {
    const asked = await drawn(
      "/products/sonic/code-findings?state=no-longer-detected&series=semgrep%2Fdefault",
    );
    expect(asked[0]).toMatchObject({ state: "no-longer-detected", series: "semgrep/default" });
    const file = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "CSV",
    );
    const at = new URL(file?.getAttribute("href") ?? "", "http://x");
    expect(at.pathname).toBe("/v1/products/sonic/code-findings.csv");
    expect(Object.fromEntries(at.searchParams)).toEqual({
      state: "no-longer-detected",
      series: "semgrep/default",
    });
  });

  it("lists the queue with each code finding opening on the build it is on", async () => {
    await drawn();
    expect(text()).toContain("src/a.c:7");
    expect(text()).toContain("master · broadcom +2");
    const link = mount.host().querySelector<HTMLAnchorElement>("td a");
    expect(link?.getAttribute("href")).toBe(
      "/products/sonic/branches-and-tags/master/variants/broadcom/code-findings/abc",
    );
  });

  it("marks a code finding in code its run declared third-party", async () => {
    await drawn(undefined, [{ ...ROWS[0], third_party: true }]);
    expect(text()).toContain("Third-party");
  });

  it("marks nothing third-party where the run declared none", async () => {
    await drawn();
    expect(text()).not.toContain("Third-party");
  });

  it("names who holds each code finding", async () => {
    await drawn();
    expect(text()).toContain("Kernel · team");
  });

  it("counts what the queue leaves out", async () => {
    await drawn();
    expect(text()).toContain("2 waiting for approval");
    expect(text()).toContain("3 open only past end of life");
    expect(text()).toContain("5 dismissed by a rule");
    expect(text()).toContain("No longer detected 40");
  });

  it("lists one state's code findings, which the address carries", async () => {
    const asked = await drawn();
    await press(mount.host(), "No longer detected 40");
    await settle();
    expect(location()).toBe("/products/sonic/code-findings?state=no-longer-detected");
    expect(asked.at(-1)).toMatchObject({ state: "no-longer-detected" });
  });

  it("narrows to the code findings nobody holds, which the address and the file carry", async () => {
    const asked = await drawn("/products/sonic/code-findings?state=open");
    tick(mount.host(), "Unassigned only");
    await settle();
    expect(location()).toBe("/products/sonic/code-findings?state=open&assigned=nobody");
    expect(asked.at(-1)).toMatchObject({ state: "open", assigned: "nobody" });
    const file = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "JSON",
    );
    expect(new URL(file?.getAttribute("href") ?? "", "http://x").searchParams.get("assigned")).toBe(
      "nobody",
    );
  });

  it("narrows to one testing method, which the address and the file carry", async () => {
    const asked = await drawn("/products/sonic/code-findings?state=open");
    change(mount.host().querySelector<HTMLSelectElement>('select[aria-label="Method"]'), "sast");
    await settle();
    expect(location()).toBe("/products/sonic/code-findings?state=open&method=sast");
    expect(asked.at(-1)).toMatchObject({ state: "open", method: "sast" });
    const file = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "JSON",
    );
    expect(new URL(file?.getAttribute("href") ?? "", "http://x").searchParams.get("method")).toBe(
      "sast",
    );
  });

  it("leaves out a method the address names that is not one", async () => {
    const asked = await drawn("/products/sonic/code-findings?method=dast");
    expect(asked.at(-1)).not.toHaveProperty("method");
  });

  it("opens Over time on every build from a queue over every build", async () => {
    await drawn("/products/sonic/code-findings?series=semgrep%2Fdefault");
    const link = Array.from(mount.host().querySelectorAll("a")).find(
      (each) => each.textContent === "Over time",
    );
    const at = new URL(link?.getAttribute("href") ?? "", "http://x");
    expect(at.pathname).toBe("/analytics/code-findings-over-time");
    expect(at.searchParams.get("branch_or_tag")).toBe("");
    expect(at.searchParams.get("variant")).toBe("");
    expect(at.searchParams.get("series")).toBe("semgrep/default");
  });

  it("asks for the build the address names", async () => {
    const asked = await drawn(
      "/products/sonic/code-findings?branch_or_tag=master&variant=broadcom",
    );
    expect(asked[0]).toMatchObject({ branch_or_tag: "master", variant: "broadcom" });
  });
});

describe("the code findings of every product read", () => {
  // The queue at `/code-findings`, for a reader of security testing material
  // in the products named.
  async function across(at: string, reads: string[]) {
    const asked: { path: string; query: unknown }[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me")
        return {
          data: {
            identity: "ana",
            name: "Ana",
            kind: "person",
            reach: reads.map((product) => ({ product, reads_security_testing: true })),
            outcomes: [],
          },
        };
      if (path.includes("code-findings")) {
        asked.push({ path, query: (init as { params: { query: unknown } }).params.query });
        return {
          data: {
            items: [
              { ...ROW, product: "sonic", product_name: "SONiC" },
              { ...ROW, product: "edge" },
            ],
            total: 2,
            states: { open: 2 },
            waiting: 0,
            ruled: 1,
            past_end_of_life: 0,
          },
        };
      }
      return undefined;
    });
    // Signed in already, as the application is by the time a screen draws.
    const queries = client();
    queries.setQueryData(["whoami"], {
      identity: "ana",
      name: "Ana",
      kind: "person",
      reach: reads.map((product) => ({ product, reads_security_testing: true })),
      outcomes: [],
    });
    mount.render(screen(<CodeFindings />, at, "/code-findings", queries));
    await settle();
    return asked;
  }

  it("asks the queue across products and opens each row in its own product", async () => {
    const asked = await across("/code-findings?state=open&assigned=nobody", ["sonic", "edge"]);
    expect(asked).toEqual([
      {
        path: "/v1/code-findings",
        query: { limit: 50, offset: 0, state: "open", assigned: "nobody" },
      },
    ]);
    const hrefs = Array.from(mount.host().querySelectorAll("td a")).map((each) =>
      each.getAttribute("href"),
    );
    expect(hrefs).toContain(
      "/products/sonic/branches-and-tags/master/variants/broadcom/code-findings/abc",
    );
    expect(hrefs).toContain(
      "/products/edge/branches-and-tags/master/variants/broadcom/code-findings/abc",
    );
    expect(hrefs).toContain("/products/sonic");
    expect(text()).toContain("SONiC");
    expect(text()).toContain("Code findings in every product you read");
  });

  it("offers the file across products and no suppression rules, which are one product's", async () => {
    await across("/code-findings", ["sonic"]);
    const files = Array.from(mount.host().querySelectorAll("a.btn")).map((each) =>
      each.getAttribute("href"),
    );
    expect(files.some((each) => each?.startsWith("/v1/code-findings.csv"))).toBe(true);
    expect(text()).not.toContain("Suppression rules");
    const ruled = Array.from(mount.host().querySelectorAll("a")).find((each) =>
      each.textContent?.includes("dismissed by a rule"),
    );
    expect(ruled?.getAttribute("href")).toBe("/code-findings?state=dismissed");
  });

  it("says a subtree needs one build and asks nothing", async () => {
    const asked = await across("/code-findings?beneath=frr", ["sonic"]);
    expect(asked).toEqual([]);
    expect(text()).toContain("This needs one build.");
  });

  it("says the reader reads code findings nowhere and asks nothing", async () => {
    const asked = await across("/code-findings", []);
    expect(asked).toEqual([]);
    expect(text()).toContain("You don't read code findings in any product.");
  });
});
