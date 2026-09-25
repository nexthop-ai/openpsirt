// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Count, known, type Readable } from "./Count";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

const pending: Readable = { isPending: true, isError: false, error: null };
const loaded: Readable = { isPending: false, isError: false, error: null };
const failed: Readable = { isPending: false, isError: true, error: new Error("down") };

let root: Root;
let host: HTMLDivElement;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

const draw = (of: Readable | Readable[]) =>
  act(() => root.render(<Count of={of}>{() => (0).toLocaleString()}</Count>));

describe("a count", () => {
  it("shows no digit while its read is in flight", () => {
    draw(pending);
    expect(host.textContent).not.toMatch(/\d/);
    expect(host.querySelector('[aria-busy="true"]')).not.toBeNull();
  });

  it("shows no digit while any read a sum depends on is in flight", () => {
    draw([loaded, pending]);
    expect(host.textContent).not.toMatch(/\d/);
  });

  it("shows the figure once every read has answered", () => {
    draw([loaded, loaded]);
    expect(host.textContent).toBe("0");
  });

  it("shows a dash when a read failed", () => {
    draw([loaded, failed]);
    expect(host.textContent).toBe("—");
  });
});

describe("an empty state", () => {
  it("is drawn only once every read has answered", () => {
    expect(known(pending)).toBe(false);
    expect(known([loaded, failed])).toBe(false);
    expect(known([loaded, loaded])).toBe(true);
  });
});
