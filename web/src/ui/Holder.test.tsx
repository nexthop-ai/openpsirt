// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Holder, type Held } from "./Holder";
import { mounted, screen, serve, settle, type Answer } from "../test/mount";
import { change, type Init } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ANA = { identity: "ana", name: "Ana", admin: false, kind: "person", reach: [], outcomes: [] };

async function drawn(
  props: { undisclosed?: boolean; value?: { identity: string; name?: string } } = {},
  holders: Answer = {
    data: {
      items: [
        { kind: "person", identity: "ana", name: "Ana" },
        { kind: "team", identity: "kernel", name: "Kernel" },
      ],
    },
  },
) {
  const spy = serve((path) => {
    if (path === "/v1/session/me") return { data: ANA };
    if (path === "/v1/products/{product}/holders") return holders;
    return undefined;
  });
  const onPick = vi.fn<(held: Held | null) => void>();
  mount.render(screen(<Holder product="sonic" onPick={onPick} {...props} />));
  await settle();
  const box = mount.host().querySelector<HTMLInputElement>('input[role="combobox"]');
  if (!box) throw new Error("no holder box");
  await act(async () => box.focus());
  await settle();
  const asked = () =>
    (spy.mock.calls as unknown as [string, Init][])
      .filter(([path]) => path === "/v1/products/{product}/holders")
      .map(([, init]) => init.params?.query);
  return { box, onPick, asked };
}

const options = () =>
  Array.from(mount.host().querySelectorAll<HTMLButtonElement>('[role="option"] button')).map(
    (each) => each.textContent,
  );

function key(box: HTMLInputElement, name: string) {
  act(() => {
    box.dispatchEvent(new KeyboardEvent("keydown", { key: name, bubbles: true }));
  });
}

describe("choosing who holds something", () => {
  it("offers the reader first and once, then nobody, then everybody else", async () => {
    await drawn();
    expect(options()).toEqual(["Ana you", "No one", "Kernel team"]);
  });

  it("offers the reader nothing they already hold", async () => {
    await drawn({ value: { identity: "ana", name: "Ana" } });
    expect(options()[0]).toBe("No one");
  });

  it("asks only for people who may read an undisclosed finding", async () => {
    const { asked, box } = await drawn({ undisclosed: true });
    expect(asked()[0]).toEqual({ visibility: "private", limit: 25 });
    change(box, " ker ");
    await settle();
    expect(asked().at(-1)).toEqual({ visibility: "private", q: "ker", limit: 25 });
  });

  it("picks from the keyboard", async () => {
    const { box, onPick } = await drawn();
    key(box, "ArrowDown");
    key(box, "ArrowDown");
    key(box, "ArrowDown");
    key(box, "Enter");
    expect(onPick).toHaveBeenCalledWith({ kind: "team", identity: "kernel", name: "Kernel" });
  });

  it("picks nobody, which takes the holder away", async () => {
    const { onPick } = await drawn();
    const nobody = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "No one",
    );
    await act(async () => nobody?.click());
    expect(onPick).toHaveBeenCalledWith(null);
  });

  it("says the people here could not be searched", async () => {
    await drawn({}, { status: 503 });
    expect(mount.host().textContent).toContain("Couldn’t search the people here.");
  });
});
