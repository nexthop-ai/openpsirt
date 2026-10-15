// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { VEX } from "./VEX";
import { accept, location, mounted, screen, serve, settle } from "../test/mount";
import { only, press, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ISSUANCE = "/v1/products/{product}/streams/{stream}/variants/{variant}/vex/issuance";

async function drawn(at = "/products/sonic/streams/master/variants/arm/vex") {
  const read = serve((path) =>
    path === ISSUANCE
      ? {
          data: {
            changed: true,
            items: [
              { version: 2, issued_at: "2026-01-01T00:00:00Z", issued_by: "ana", digest: "abc" },
            ],
          },
        }
      : undefined,
  );
  const sent = accept(() => ({ data: { version: 3 } }));
  mount.render(screen(<VEX />, at, "/products/:product/streams/:stream/variants/:variant/vex"));
  await settle();
  const asked = () =>
    (read.mock.calls as unknown as [string, Init][])
      .filter(([path]) => path === ISSUANCE)
      .map(([, init]) => init.params?.query);
  return { asked, sent };
}

const hrefs = () =>
  Array.from(mount.host().querySelectorAll("a")).map((a) => a.getAttribute("href") ?? "");

describe("the VEX document for one build", () => {
  it("asks for our own document unless the supplier tab is picked", async () => {
    const { asked, sent } = await drawn();
    expect(asked()[0]).toEqual({});
    await press(mount.host(), "Record that it went out");
    await settle();
    expect(only(sent)[1].params?.query).toEqual({});
    expect(mount.host().textContent).toContain("Recorded as version 3.");
  });

  it("carries the supplier kind into every read, record and link", async () => {
    const { asked, sent } = await drawn();
    await press(mount.host(), "With supplier statements");
    await settle();
    expect(location()).toContain("kind=with-suppliers");
    expect(asked().at(-1)).toEqual({ kind: "with-suppliers" });
    await press(mount.host(), "Record that it went out");
    await settle();
    expect(only(sent)[1].params?.query).toEqual({ kind: "with-suppliers" });
    const issued = hrefs().filter((href) => href.includes("/vex"));
    expect(issued.length).toBeGreaterThan(2);
    for (const href of issued) expect(href).toContain("kind=with-suppliers");
  });

  it("lets go of what the other tab recorded", async () => {
    await drawn();
    await press(mount.host(), "Record that it went out");
    await settle();
    await press(mount.host(), "With supplier statements");
    await settle();
    expect(mount.host().textContent).not.toContain("Recorded as version 3.");
  });
});
