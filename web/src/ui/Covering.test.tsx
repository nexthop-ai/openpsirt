// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { describe, expect, it } from "vitest";
import { Covering, type Sitting } from "./Covering";
import { change, press } from "../test/controls";
import { mounted } from "../test/mount";

const mount = mounted();

// A place under a consumer, named by the component at its end.
function under(consumer: string, component: string): Sitting {
  return {
    place: `${consumer}/${component}`,
    component: "libnl",
    chain: [{ component: "image" }, { component: consumer }, { component }],
  } as Sitting;
}

// Thirteen places under one consumer, enough for the filter to be offered,
// and one under another.
const places: Sitting[] = [
  ...Array.from({ length: 12 }, (_, at) => under("kernel", `module-${at}`)),
  under("kernel", "netfilter"),
  under("sshd", "sshd"),
];

const answered = { isPending: false, isError: false, error: null };

// The control as a form holds it, with what it excluded readable afterwards.
const left: { now: Set<string> } = { now: new Set() };
function Holding() {
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  return (
    <Covering
      places={places}
      excluded={excluded}
      onChange={(next) => {
        left.now = next;
        setExcluded(next);
      }}
      matching={2}
      differing={1}
      reach={answered}
    />
  );
}

function groupBox(consumer: string): HTMLInputElement {
  const label = Array.from(mount.host().querySelectorAll(".grp label")).find(
    (each) => each.querySelector(".id")?.textContent === consumer,
  );
  const box = label?.querySelector<HTMLInputElement>('input[type="checkbox"]');
  if (!box) throw new Error(`no group ${consumer}`);
  return box;
}

describe("the places a decision covers", () => {
  it("leaves out only the rows the filter shows when a group is unticked", async () => {
    left.now = new Set();
    mount.render(<Holding />);
    await press(mount.host(), "Exclude places…");
    change(mount.host().querySelector<HTMLInputElement>(".locfilter"), "netfilter");
    expect(mount.host().querySelector(".grp .cnt")?.textContent).toBe("1 of 1");
    act(() => groupBox("kernel").click());
    expect([...left.now]).toEqual(["kernel/netfilter"]);
    expect(mount.host().textContent).toContain("13 of 14 covered · 1 left open under kernel");
  });

  it("covers everything again on Cover all", async () => {
    left.now = new Set();
    mount.render(<Holding />);
    await press(mount.host(), "Exclude places…");
    act(() => groupBox("sshd").click());
    expect([...left.now]).toEqual(["sshd/sshd"]);
    await press(mount.host(), "Cover all");
    expect(left.now.size).toBe(0);
    expect(mount.host().textContent).toContain("2 consumers");
  });

  it("leaves out one place from inside an opened group", async () => {
    left.now = new Set();
    mount.render(<Holding />);
    await press(mount.host(), "Exclude places…");
    await press(mount.host(), "▸");
    const place = Array.from(mount.host().querySelectorAll("label.loc")).find(
      (each) => each.querySelector(".id")?.textContent === "module-3",
    );
    act(() => place?.querySelector<HTMLInputElement>("input")?.click());
    expect([...left.now]).toEqual(["kernel/module-3"]);
    expect(groupBox("kernel").indeterminate).toBe(true);
  });
});
