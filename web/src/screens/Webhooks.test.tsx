// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WebhookDelivery, Webhooks } from "./Webhooks";
import { answer, client, mounted, screen, serve, settle, watchInvalidations } from "../test/mount";
import { labeled, only, press, change } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const DESTINATIONS = [
  {
    name: "sec",
    kind: "*",
    platform: "webhook",
    host: "hooks.example.com",
    sent: 4,
    failing: 2,
    because: "502",
  },
  { name: "chat", kind: "*", platform: "slack", channel: "#security", sent: 1 },
];

function served() {
  serve((path) => (path === "/v1/outbound" ? { data: { items: DESTINATIONS } } : undefined));
}

const text = () => mount.host().textContent ?? "";

// The add button in the drawer's footer, which reads the same as the one that
// opens it.
const submit = () =>
  Array.from(mount.host().querySelectorAll("button"))
    .filter((each) => each.textContent?.trim() === "Add webhook")
    .at(-1);

describe("the webhooks an administrator configures", () => {
  it("lists only webhooks, and retires the one named", async () => {
    served();
    const gone = answer("DELETE", () => ({ data: {} }));
    const queries = client();
    const invalidated = watchInvalidations(queries);
    mount.render(screen(<Webhooks />, "/", "*", queries));
    await settle();
    expect(text()).toContain("hooks.example.com");
    expect(text()).not.toContain("#security");
    await press(mount.host(), "Retire");
    await settle();
    expect(only(gone)[1].params?.path).toEqual({ name: "sec", kind: "*" });
    expect(invalidated()).toContain("outbound");
  });

  it("holds the add back until the signing secret is long enough", async () => {
    served();
    const added = answer("POST", () => ({ data: {} }));
    mount.render(screen(<Webhooks />));
    await settle();
    await press(mount.host(), "Add webhook");
    change(labeled(mount.host(), "Name"), " sec2 ");
    change(labeled(mount.host(), "Kind"), " ");
    change(labeled(mount.host(), "URL"), "https://hooks.example.com/x");
    change(labeled(mount.host(), "Signing secret"), "short");
    expect(submit()?.disabled).toBe(true);
    change(labeled(mount.host(), "Signing secret"), "a long enough secret");
    expect(submit()?.disabled).toBe(false);
    await act(async () => submit()?.click());
    await settle();
    // A blank kind is every kind, and nothing is sent with the spaces typed.
    expect(only(added)[1].body).toEqual({
      name: "sec2",
      kind: "*",
      url: "https://hooks.example.com/x",
      secret: "a long enough secret",
    });
  });
});

describe("delivery to every destination", () => {
  it("names a webhook by its host and a channel by its channel, and counts failures", async () => {
    served();
    mount.render(screen(<WebhookDelivery />));
    await settle();
    expect(text()).toContain("hooks.example.com");
    expect(text()).toContain("#security");
    expect(mount.host().querySelector(".state.bad")?.getAttribute("title")).toBe("502");
    expect(text()).toContain("nothing said");
  });
});
