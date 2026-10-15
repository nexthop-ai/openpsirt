// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Branch } from "./Branch";
import { mounted, screen, serve, settle, type Answer } from "../test/mount";
import type { Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// The list of lines answers a retired one only when asked to include them, as
// the server does.
async function drawn(stream: string, streams: Answer) {
  const spy = serve((path, init) => {
    if (path === "/v1/products/{product}/streams") {
      const retired = (init as Init).params?.query?.retired === true;
      const items = (streams.data as { items?: { retired?: boolean }[] } | undefined)?.items;
      return items
        ? { data: { items: items.filter((each) => retired || !each.retired) } }
        : streams;
    }
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: false,
          kind: "person",
          reach: [],
          outcomes: [],
        },
      };
    return { data: { items: [], total: 0 } };
  });
  mount.render(
    screen(<Branch />, `/products/sonic/streams/${stream}`, "/products/:product/streams/:stream"),
  );
  await settle();
  return spy;
}

const STREAMS: Answer = {
  data: {
    items: [
      { name: "master", kind: "branch" },
      { name: "202411.1", kind: "tag" },
      { name: "202305.9", kind: "tag", retired: true },
    ],
  },
};

describe("a line's own address", () => {
  it("opens a tag as a release", async () => {
    await drawn("202411.1", STREAMS);
    expect(mount.host().querySelector("h2")?.textContent).not.toBe("Variants");
    expect(mount.host().textContent).toContain("202411.1");
  });

  it("resolves a retired tag as a tag rather than as a branch", async () => {
    await drawn("202305.9", STREAMS);
    expect(mount.host().querySelector("h2")?.textContent).not.toBe("Variants");
  });

  it("opens a branch as the variants it is built as", async () => {
    await drawn("master", STREAMS);
    expect(mount.host().querySelector("h2")?.textContent).toBe("Variants");
  });

  it("says it could not tell which a line is", async () => {
    await drawn("master", { status: 503 });
    expect(mount.host().textContent).toContain("This could not be resolved to a branch or a tag.");
  });
});
