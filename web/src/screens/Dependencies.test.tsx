// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dependencies } from "./Dependencies";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { change, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const AT = "/products/sonic/branches-and-tags/master/variants/arm/dependencies";
const PATTERN =
  "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant/dependencies";
const BUILD = "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}";

const node = (component: string, of: Record<string, unknown> = {}) => ({
  component,
  version: "1.0",
  findings: 0,
  beneath: 0,
  children: 0,
  ...of,
});

function who(reach: object[]) {
  return {
    data: { identity: "ana", name: "Ana", admin: false, kind: "person", reach, outcomes: [] },
  };
}

async function drawn(reach: object[], at = AT) {
  const spy = serve((path, init) => {
    const query = (init as Init).params?.query ?? {};
    if (path === "/v1/session/me") return who(reach);
    if (path === `${BUILD}/components/mine`)
      return {
        data: {
          complete: false,
          items: [
            {
              component: "sonic-swss",
              version: "1.0",
              placed: true,
              depth: 0,
              findings: 2,
              beneath: 5,
            },
            {
              component: "libnl",
              version: "3.7",
              placed: true,
              depth: 1,
              beneath: 3,
              ecosystem: "deb",
            },
            { component: "stray", version: "0.1", placed: false, findings: 1 },
          ],
        },
      };
    if (path === `${BUILD}/components`)
      return query.q === "nothing"
        ? { data: { items: [] } }
        : query.q
          ? {
              data: {
                items: [node("openssl", { version: "3.0", beneath: 600, ecosystem: "deb" })],
              },
            }
          : {
              data: {
                components: 40,
                edges: 80,
                unmatched: 2,
                root: node("sonic", { children: 1, beneath: 7 }),
                items: [node("sonic-swss", { children: 2, beneath: 7 })],
              },
            };
    if (path === `${BUILD}/component-groups`)
      return query.ecosystem
        ? {
            data: {
              items: [
                {
                  key: "pkg:cargo/addr2line",
                  versions: ["0.25.1"],
                  components: 1,
                  open: 1,
                  fixed: 0,
                  open_by_severity: { high: 1 },
                  component: { name: "addr2line", version: "0.25.1", ecosystem: "cargo" },
                },
              ],
            },
          }
        : query.by === "ecosystem"
          ? {
              data: {
                items: [
                  {
                    key: "cargo",
                    versions: [],
                    components: 3,
                    open: 2,
                    fixed: 1,
                    open_by_severity: {},
                  },
                  {
                    key: "none",
                    versions: [],
                    components: 1,
                    open: 0,
                    fixed: 0,
                    open_by_severity: {},
                  },
                ],
              },
            }
          : {
              data: {
                items: [
                  {
                    key: "pkg:github/sonic-net/sonic-swss",
                    versions: ["2126d2752826"],
                    components: 1,
                    open: 4,
                    fixed: 2,
                    open_by_severity: { critical: 4 },
                    component: {
                      name: "swss",
                      version: "1.0.0",
                      ecosystem: "github",
                      namespace: "sonic-net",
                    },
                  },
                ],
              },
            };
    if (path === `${BUILD}/components/{component}/around`)
      return { data: { below: [node("libnl"), node("zlib")] } };
    return undefined;
  });
  mount.render(screen(<Dependencies />, at, PATTERN));
  await settle();
  return () => (spy.mock.calls as unknown as [string][]).map(([path]) => path);
}

const text = () => mount.host().textContent ?? "";

describe("the dependency paths somebody without a role in the product sees", () => {
  it("traces only their own work, and says the counts under-report", async () => {
    const asked = await drawn([]);
    expect(asked()).toContain(`${BUILD}/components/mine`);
    expect(asked()).not.toContain(`${BUILD}/components`);
    expect(text()).toContain("2 here");
    expect(text()).toContain("Placed nowhere");
    expect(text()).toContain("Not all of it.");
    const beneath = Array.from(mount.host().querySelectorAll("a")).find(
      (a) => a.textContent === "3 beneath",
    );
    expect(beneath?.getAttribute("href")).toContain("beneath=libnl");
    expect(beneath?.getAttribute("href")).toContain("beneath_version=3.7");
    expect(beneath?.getAttribute("href")).toContain("beneath_ecosystem=deb");
  });
});

describe("the whole tree somebody with a role reads", () => {
  const REACH = [{ product: "sonic" }];

  it("opens a branch by reading what it pulls in", async () => {
    const asked = await drawn(REACH);
    expect(text()).toContain("40 components, 80 edges");
    expect(text()).toContain("2 unmatched");
    const open = mount
      .host()
      .querySelector<HTMLButtonElement>('button.rule.has[aria-expanded="false"]');
    await act(async () => open?.click());
    await settle();
    expect(asked()).toContain(`${BUILD}/components/{component}/around`);
    expect(text()).toContain("zlib");
  });

  it("searches by name in the address, and selecting a hit keeps what tells it apart", async () => {
    await drawn(REACH);
    const box = mount
      .host()
      .querySelector<HTMLInputElement>('input[aria-label="Find a component"]');
    change(box, " openssl ");
    await act(async () => box?.form?.requestSubmit());
    await settle();
    expect(location()).toContain("q=openssl");
    const hit = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "openssl",
    );
    await act(async () => hit?.click());
    await settle();
    expect(location()).toContain("at=openssl");
    expect(location()).toContain("version=3.0");
    expect(location()).toContain("ecosystem=deb");
  });

  it("says nothing is called what was searched for", async () => {
    await drawn(REACH, `${AT}?q=nothing`);
    expect(text()).toContain('Nothing here is called "nothing".');
    expect(text()).toContain("Back to the tree");
  });
});

describe("the components listed by repository and by ecosystem", () => {
  const REACH = [{ product: "sonic" }];
  const link = (name: string) =>
    Array.from(mount.host().querySelectorAll("a"))
      .filter((a) => a.textContent === name)
      .map((a) => a.getAttribute("href") ?? "");

  it("lists a repository at the commit it ships, opening its subtree on this build", async () => {
    await drawn(REACH, `${AT}?list=repository`);
    expect(text()).toContain("pkg:github/sonic-net/sonic-swss");
    expect(text()).toContain("2126d2752826");
    const [findings] = link("Findings");
    expect(findings).toContain("/variants/arm/findings?");
    expect(findings).toContain("beneath=swss");
    expect(findings).toContain("beneath_version=1.0.0");
    const [burn] = link("Burndown");
    expect(burn).toContain("/analytics/findings-burndown?");
    expect(burn).toContain("beneath=swss");
    expect(burn).toContain("beneath_namespace=sonic-net");
  });

  it("chooses an ecosystem's burndown by its purl prefix, and opens its packages", async () => {
    await drawn(REACH, `${AT}?list=ecosystem`);
    expect(link("Burndown")).toEqual([
      "/analytics/findings-burndown?branch_or_tag=master&variant=arm&purl=pkg%3Acargo%2F",
    ]);
    expect(link("cargo")[0]).toContain("list=ecosystem&ecosystem=cargo");
    await act(async () =>
      Array.from(mount.host().querySelectorAll("a"))
        .find((a) => a.textContent === "cargo")
        ?.click(),
    );
    await settle();
    expect(text()).toContain("pkg:cargo/addr2line");
    expect(link("Findings")[0]).toContain("component=addr2line");
    expect(link("Burndown")[0]).toContain("purl=pkg%3Acargo%2Faddr2line");
  });

  it("switches back to the tree from a list", async () => {
    await drawn(REACH, `${AT}?list=repository`);
    const tree = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Tree",
    );
    await act(async () => tree?.click());
    await settle();
    expect(location()).not.toContain("list=");
    expect(mount.host().querySelector(".tree")).not.toBeNull();
    expect(text()).not.toContain("pkg:github/sonic-net/sonic-swss");
  });
});
