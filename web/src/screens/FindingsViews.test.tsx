// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ByBump, ByComponent, Pager, Peek, Sits } from "./FindingsViews";
import type { Row } from "./list";
import { mounted, screen, serve, settle } from "../test/mount";
import { press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const text = () => mount.host().textContent ?? "";
const href = (name: string) =>
  Array.from(mount.host().querySelectorAll("a"))
    .find((a) => a.textContent === name)
    ?.getAttribute("href") ?? "";

describe("where a finding sits", () => {
  const sits = (row: Partial<Row>) => {
    mount.render(<Sits row={row as Row} />);
    return text();
  };

  it("names the build where a row folds several", () => {
    expect(sits({ builds: 3, stream: "master", variant: "arm" })).toContain("one of 3 builds");
  });

  it("says when nothing records what pulls it in", () => {
    expect(sits({})).toBe("nothing records what pulls this in");
  });

  it("says when nothing places its parent under the build", () => {
    expect(sits({ parent: "libssl", chains: 2 })).toContain("nothing places it under the build");
  });

  it("collapses the middle of a long chain into a count", () => {
    const said = sits({ owner: "sonic-swss", parent: "libnl", middle: 2, chains: 4 });
    expect(said).toContain("sonic-swss→+2→libnl");
    expect(said).toContain("one of 4");
  });

  it("draws an owner that is its own parent once", () => {
    expect(sits({ owner: "zlib", parent: "zlib" })).toBe("zlib");
  });
});

describe("the open findings by component", () => {
  async function drawn(query: Record<string, unknown>, total = 2) {
    serve((path) =>
      path === "/v1/products/{product}/findings/components"
        ? {
            data: {
              total,
              items: [
                {
                  component: "zlib",
                  version: "1.2",
                  issues: 4,
                  places: 9,
                  worst: "critical",
                  by_severity: { critical: 1, high: 3 },
                  exploited: true,
                  upgrades: [
                    { to: "1.3", closes: 4 },
                    { to: "1.4", closes: 4 },
                    { to: "2.0", closes: 1 },
                  ],
                },
              ],
            },
          }
        : undefined,
    );
    const acts = { onHide: vi.fn(), onOnly: vi.fn(), onSort: vi.fn(), onPage: vi.fn() };
    mount.render(
      screen(
        <ByComponent
          at={{ product: "sonic", stream: "master" }}
          query={query}
          offset={0}
          size={50}
          {...acts}
        />,
      ),
    );
    await settle();
    return acts;
  }

  it("links a file narrowed the same way, without the page", async () => {
    await drawn({ severity: "high", ecosystem: ["deb", "npm"], limit: 50, offset: 0 });
    const csv = href("CSV");
    expect(csv).toContain("components.csv");
    expect(csv).toContain("severity=high");
    expect(csv).toContain("ecosystem=deb&ecosystem=npm");
    expect(csv).toContain("stream=master");
    expect(csv).not.toContain("limit=");
    expect(csv).not.toContain("offset=");
  });

  it("turns the worst-first order on, and off again", async () => {
    let acts = await drawn({});
    await press(mount.host(), "Worst");
    expect(acts.onSort).toHaveBeenCalledWith("severity");
    acts = await drawn({ sort: "severity" });
    expect(text()).toContain("Ordered by the worst rating in each.");
    await press(mount.host(), "Worst ▾");
    expect(acts.onSort).toHaveBeenCalledWith("");
  });

  it("narrows to a component and hides one by its name", async () => {
    const acts = await drawn({});
    await press(mount.host(), "only this");
    await press(mount.host(), "hide");
    expect(acts.onOnly).toHaveBeenCalledWith("zlib");
    expect(acts.onHide).toHaveBeenCalledWith("zlib");
  });

  it("offers the two upgrades that close the most, and says how many more there are", async () => {
    await drawn({});
    expect(text()).toContain("1.3");
    expect(text()).toContain("1 more");
    expect(text()).not.toContain("2.0");
  });

  it("pages forward from the pager", async () => {
    const acts = await drawn({}, 120);
    await press(mount.host(), "Next");
    expect(acts.onPage).toHaveBeenCalledWith(50);
  });
});

describe("the open findings by upgrade", () => {
  it("links a file narrowed the same way, and says which filters it cannot apply", async () => {
    serve((path) =>
      path === "/v1/products/{product}/fix-bundles"
        ? {
            data: {
              total: 1,
              items: [
                {
                  upstream: "openssl",
                  from: "3.0.1",
                  to: "3.0.9",
                  components: ["libssl3", "openssl"],
                  severity: "high",
                  issues: 5,
                  in: [{ stream: "master", variant: "arm" }],
                },
              ],
            },
          }
        : undefined,
    );
    mount.render(
      screen(
        <ByBump
          at={{ product: "sonic" }}
          query={{ severity: "high", component: ["libssl3"] }}
          offset={0}
          size={50}
          onPage={() => undefined}
          cannot={["age"]}
        />,
      ),
    );
    await settle();
    const csv = href("CSV");
    expect(csv).toContain("fix-bundles.csv");
    expect(csv).toContain("component=libssl3");
    expect(csv).not.toContain("limit=");
    expect(text()).toContain("Not applied here: age.");
    expect(text()).toContain("master · arm");
  });
});

describe("the pager", () => {
  it("draws nothing for a single page", () => {
    mount.render(<Pager offset={0} total={10} size={50} onGo={() => undefined} />);
    expect(text()).toBe("");
  });

  it("stops at either end", async () => {
    const onGo = vi.fn();
    mount.render(<Pager offset={100} total={120} size={50} onGo={onGo} />);
    const [previous, next] = Array.from(mount.host().querySelectorAll("button"));
    expect(next?.disabled).toBe(true);
    await act(async () => previous?.click());
    expect(onGo).toHaveBeenCalledWith(50);
  });
});

describe("a finding peeked at from the list", () => {
  it("says what pulls in each place and which are decided", async () => {
    serve((path) =>
      path.endsWith("/components/{component}")
        ? {
            data: {
              description: "A flaw in the parser.",
              places: [
                { place: "a", consumer: "sonic-swss" },
                { place: "b", chain: [{ component: "libnl" }], decision: 3 },
                { place: "c" },
              ],
            },
          }
        : { data: { items: [] } },
    );
    mount.render(
      screen(
        <Peek
          at={{ product: "sonic", stream: "master", variant: "arm" }}
          vulnerability="CVE-2026-1"
          component="zlib"
          version="1.2"
          to="/finding"
          onDecided={() => undefined}
        />,
      ),
    );
    await settle();
    expect(text()).toContain("A flaw in the parser.");
    expect(text()).toContain("under sonic-swss");
    expect(text()).toContain("under libnl");
    expect(text()).toContain("nothing records what pulls this in");
    expect(mount.host().querySelectorAll(".note")).toHaveLength(1);
  });
});
