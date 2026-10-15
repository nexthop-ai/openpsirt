// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InboxReport } from "./InboxReport";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { only, press, change } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const SENT_IN = {
  reference: "sonic-R-1",
  reported_by: "eve@example.com",
  contact: "eve@example.com",
  credit: "Eve",
  received: "2026-01-01",
  recorded_by: "ana",
  recorded_at: "2026-01-01T00:00:00Z",
};

async function drawn(report: Record<string, unknown>, may_hide = true) {
  serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: {
          identity: "ana",
          name: "Ana",
          admin: false,
          kind: "person",
          reach: [{ product: "sonic", may_hide }],
          outcomes: [],
        },
      };
    if (path === "/v1/products/{product}/reports/{reference}") return { data: report };
    if (path === "/v1/products/{product}/reports/{reference}/attachments")
      return {
        data: {
          items: [
            { token: "t1", filename: "poc.py", content_type: "text/x-python", size: 2048 },
            { token: "t2", filename: "dump.bin", redacted: true, redacted_reason: "held a key" },
          ],
        },
      };
    return undefined;
  });
  const writes = {
    post: answer("POST", () => ({ data: {} })),
    put: answer("PUT", () => ({ data: {} })),
  };
  mount.render(
    screen(
      <InboxReport />,
      "/products/sonic/inbox/sonic-R-1",
      "/products/:product/inbox/:reference",
    ),
  );
  await settle();
  return writes;
}

const text = () => mount.host().textContent ?? "";

describe("one vulnerability report", () => {
  it("records an answer to whoever sent it", async () => {
    const writes = await drawn(SENT_IN);
    expect(text()).toContain("Not answered.");
    await press(mount.host(), "Mark as answered");
    await settle();
    const [path, init] = only(writes.post);
    expect(path).toBe("/v1/products/{product}/reports/{reference}/acknowledgement");
    expect(init.params?.path).toEqual({ product: "sonic", reference: "sonic-R-1" });
  });

  it("accepts it as an issue already here, by the name typed without its spaces", async () => {
    const writes = await drawn(SENT_IN);
    const accept = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Accept",
    );
    expect(accept?.disabled).toBe(true);
    change(mount.host().querySelector<HTMLInputElement>("#accept-as"), " CVE-2026-9 ");
    await press(mount.host(), "Accept");
    await settle();
    const [path, init] = only(writes.put);
    expect(path).toBe("/v1/products/{product}/reports/{reference}/issue");
    expect(init.body).toEqual({ vulnerability: "CVE-2026-9" });
  });

  it("owes nobody an answer for a flaw found here", async () => {
    await drawn({ ...SENT_IN, found_here: true, reported_by: "bo" });
    expect(text()).toContain("Found here by bo");
    expect(text()).not.toContain("Not answered.");
  });

  it("lists its files, and says which one was removed and why", async () => {
    await drawn(SENT_IN);
    expect(mount.host().querySelector("a[href*='/v1/attachments/t1']")?.textContent).toBe("poc.py");
    expect(text()).toContain("dump.bin was removed — held a key");
  });

  it("attaches a file dropped on it", async () => {
    const writes = await drawn(SENT_IN);
    const input = mount.host().querySelector<HTMLInputElement>('input[type="file"]');
    if (!input) throw new Error("no file input");
    const file = new File(["x"], "trace.txt", { type: "text/plain" });
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
    await settle();
    const [path, init] = only(writes.post);
    expect(path).toBe("/v1/products/{product}/reports/{reference}/attachments");
    expect((init.body as FormData).get("file")).toBe(file);
  });

  it("says who accepted it, as what", async () => {
    await drawn({
      ...SENT_IN,
      disposition: "accepted",
      issue: "CVE-2026-9",
      evaluated_by: "bo",
      evaluated: "2026-01-03T00:00:00Z",
    });
    expect(text()).toContain("Accepted as CVE-2026-9");
  });
});

describe("one vulnerability report read by somebody who does not work it", () => {
  it("offers no act on it", async () => {
    await drawn(SENT_IN, false);
    const mark = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Mark as answered",
    );
    expect(mark?.hidden).toBe(true);
    expect(text()).toContain("Not judged yet.");
    expect(mount.host().querySelector('input[type="file"]')).toBeNull();
  });
});
