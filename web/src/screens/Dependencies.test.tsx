// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dependencies } from "./Dependencies";
import { location, mounted, screen, serve, settle } from "../test/mount";
import { change, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const AT = "/products/sonic/streams/master/variants/arm/dependencies";
const PATTERN = "/products/:product/streams/:stream/variants/:variant/dependencies";
const BUILD = "/v1/products/{product}/streams/{stream}/variants/{variant}";

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
