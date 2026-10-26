// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InboxReport, actSaid } from "./InboxReport";
import { answer, mounted, screen, serve, settle } from "../test/mount";
import { button, only, press, change } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const SENT_IN = {
  product: "sonic",
  reference: "sonic-R-1",
  reported_by: "eve@example.com",
  contact: "eve@example.com",
  credit: "Eve",
  received: "2026-01-01",
  recorded_by: "ana",
  recorded_at: "2026-01-01T00:00:00Z",
};

async function drawn(
  report: Record<string, unknown>,
  may_hide = true,
  more: Record<string, unknown> = {},
) {
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
    if (path in more) return { data: more[path] };
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
  it("records a message sent to whoever sent it, which is the acknowledgement", async () => {
    const writes = await drawn(SENT_IN);
    expect(text()).toContain("Not answered.");
    change(
      mount.host().querySelector<HTMLTextAreaElement>('textarea[aria-label="Message"]'),
      "Thanks.",
    );
    await press(mount.host(), "Record");
    await settle();
    const [path, init] = only(writes.post);
    expect(path).toBe("/v1/products/{product}/reports/{reference}/messages");
    expect(init.params?.path).toEqual({ product: "sonic", reference: "sonic-R-1" });
    expect(init.body).toEqual({ direction: "sent", body: "Thanks." });
  });

  it("says when it was acknowledged, and lists what was written", async () => {
    await drawn({ ...SENT_IN, acknowledged: "2026-01-02", acknowledged_by: "ana" }, true, {
      "/v1/products/{product}/reports/{reference}/messages": {
        items: [
          {
            id: 1,
            direction: "received",
            dated: "2026-01-03",
            body: "Any news?",
            logged_by: "ana",
            logged_at: "2026-01-03T00:00:00Z",
          },
        ],
      },
    });
    expect(text()).toContain("Acknowledged 2026-01-02 by ana");
    expect(text()).not.toContain("Not answered.");
    expect(text()).toContain("Any news?");
  });

  it("edits what it says, and keeps the original on screen", async () => {
    const writes = await drawn({ ...SENT_IN, summary: "Now.", editable: true, edits: 1 }, true, {
      "/v1/products/{product}/reports/{reference}/revisions": {
        items: [
          {
            version: 1,
            summary: "At first.",
            replaced_by: "ana",
            replaced_at: "2026-01-02T00:00:00Z",
          },
        ],
      },
    });
    expect(text()).toContain("Original");
    expect(text()).toContain("At first.");
    await press(mount.host(), "Edit");
    change(mount.host().querySelector<HTMLInputElement>("#report-title"), " A socket answers ");
    await press(mount.host(), "Save");
    await settle();
    const [path, init] = only(writes.put);
    expect(path).toBe("/v1/products/{product}/reports/{reference}");
    expect(init.body).toMatchObject({ title: "A socket answers", summary: "Now." });
  });

  it("offers no edit once it is judged", async () => {
    await drawn({ ...SENT_IN, summary: "Now.", editable: false, disposition: "rejected" });
    expect(() => button(mount.host(), "Edit")).toThrow('no button reads "Edit"');
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
    // The last file input is the files card's own. The ones before it attach
    // a file inside the text of a message or a note.
    const inputs = mount.host().querySelectorAll<HTMLInputElement>('input[type="file"]');
    const input = inputs[inputs.length - 1];
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
    await drawn({ ...SENT_IN, editable: true }, false);
    for (const label of ["Record", "Edit", "Note"]) {
      expect(() => button(mount.host(), label)).toThrow(`no button reads "${label}"`);
    }
    expect(text()).toContain("Not judged yet.");
    expect(mount.host().querySelector('input[type="file"]')).toBeNull();
  });
});

describe("a report's history", () => {
  it.each([
    [
      { act: "assigned", at: "", to: "triage", to_team: true, rule: 3 },
      "Routed to triage (team) by a routing rule",
    ],
    [{ act: "assigned", at: "", to: "bo", to_name: "Bo" }, "Assigned to Bo"],
    [{ act: "edited", at: "", version: 2 }, "Edited, version 2 kept"],
    [{ act: "sent", at: "", dated: "2026-01-02" }, "Message sent on 2026-01-02"],
    [{ act: "ruling-settled", at: "", disposition: "rejected" }, "Ruling in force: Rejected"],
  ] as const)("says %o as %s", (row, said) => {
    expect(actSaid(row as never)).toBe(said);
  });
});
