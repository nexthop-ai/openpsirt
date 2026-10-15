// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChatChannels } from "./ChatChannels";
import { change, press } from "../test/controls";
import { accept, answer, mounted, screen, serve, settle, type Sent } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

function serving(items: unknown[] = []) {
  serve((path) => (path === "/v1/outbound" ? { data: { items } } : undefined));
}

// The submit button of the open form, which carries the same words as the
// button that opened it.
function submit(): HTMLButtonElement {
  const all = Array.from(mount.host().querySelectorAll("button")).filter(
    (each) => each.textContent?.trim() === "Add channel",
  );
  const last = all[all.length - 1];
  if (!last) throw new Error("no form is open");
  return last;
}

function field(id: string): HTMLInputElement | HTMLSelectElement | null {
  return mount.host().querySelector(`#${id}`);
}

const bodyOf = (sent: Sent) => (sent[1] as { body: unknown }).body;

describe("the chat channels", () => {
  it("adds a Zulip channel with its topic, scoped to one team", async () => {
    serving();
    const sent = accept(() => ({ data: {} }));
    mount.render(screen(<ChatChannels platforms={["slack", "zulip"]} />));
    await settle();
    await press(mount.host(), "Add channel");
    change(field("declare-name"), " kernel-psirt ");
    change(field("chat-platform"), "zulip");
    change(field("declare-channel"), " security ");
    change(field("declare-topic"), " OpenPSIRT ");
    change(field("chat-scope"), "team");
    expect(submit().disabled).toBe(true);
    change(field("declare-team"), " kernel ");
    act(() => submit().click());
    await settle();
    expect(sent().map(bodyOf)).toEqual([
      {
        name: "kernel-psirt",
        kind: "*",
        platform: "zulip",
        channel: "security",
        topic: "OpenPSIRT",
        team: "kernel",
      },
    ]);
  });

  it("sends no topic for a Slack channel, and a product for a product channel", async () => {
    serving();
    const sent = accept(() => ({ data: {} }));
    mount.render(screen(<ChatChannels platforms={["slack", "zulip"]} />));
    await settle();
    await press(mount.host(), "Add channel");
    change(field("chat-platform"), "zulip");
    change(field("declare-topic"), "typed before switching");
    change(field("chat-platform"), "slack");
    change(field("declare-name"), "sonic");
    change(field("declare-kind"), "finding.assigned");
    change(field("declare-channel"), "C0123ABCD");
    change(field("chat-scope"), "product");
    change(field("declare-product"), "sonic");
    act(() => submit().click());
    await settle();
    expect(sent().map(bodyOf)).toEqual([
      {
        name: "sonic",
        kind: "finding.assigned",
        platform: "slack",
        channel: "C0123ABCD",
        product: "sonic",
      },
    ]);
  });

  it("retires the channel on the row pressed, and lists stored channels with no platform", async () => {
    serving([
      { name: "hooks", kind: "*", platform: "webhook" },
      {
        name: "kernel-psirt",
        kind: "*",
        platform: "zulip",
        channel: "security",
        topic: "x",
        team: "kernel",
      },
    ]);
    const removed = answer("DELETE", () => ({ data: {} }));
    mount.render(screen(<ChatChannels platforms={[]} />));
    await settle();
    expect(mount.host().textContent).toContain("No chat platform is configured.");
    expect(mount.host().textContent).toContain("Team kernel");
    expect(mount.host().textContent).not.toContain("hooks");
    await press(mount.host(), "Retire");
    await settle();
    expect(removed()[0]?.[1]).toEqual({ params: { path: { name: "kernel-psirt", kind: "*" } } });
  });
});
