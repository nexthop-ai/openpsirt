// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { Count, known, type Readable } from "./Count";

const pending: Readable = { isPending: true, isError: false, error: null };
const loaded: Readable = { isPending: false, isError: false, error: null };
const failed: Readable = { isPending: false, isError: true, error: new Error("down") };

const mount = mounted();

const draw = (of: Readable | Readable[]) =>
  mount.render(<Count of={of}>{() => (0).toLocaleString()}</Count>);

describe("a count", () => {
  it("shows no digit while its read is in flight", () => {
    draw(pending);
    expect(mount.host().textContent).not.toMatch(/\d/);
    expect(mount.host().querySelector('[aria-busy="true"]')).not.toBeNull();
  });

  it("shows no digit while any read a sum depends on is in flight", () => {
    draw([loaded, pending]);
    expect(mount.host().textContent).not.toMatch(/\d/);
  });

  it("shows the figure once every read has answered", () => {
    draw([loaded, loaded]);
    expect(mount.host().textContent).toBe("0");
  });

  it("shows a dash when a read failed", () => {
    draw([loaded, failed]);
    expect(mount.host().textContent).toBe("—");
  });
});

describe("an empty state", () => {
  it("is drawn only once every read has answered", () => {
    expect(known(pending)).toBe(false);
    expect(known([loaded, failed])).toBe(false);
    expect(known([loaded, loaded])).toBe(true);
  });
});
