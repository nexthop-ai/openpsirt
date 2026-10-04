// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { Link } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { location, mounted, screen } from "../test/mount";
import { useRowOpener } from "./opens";

const mount = mounted();

afterEach(() => window.getSelection()?.removeAllRanges());

function Row() {
  const opener = useRowOpener();
  const [picked, setPicked] = useState(false);
  return (
    <table>
      <tbody>
        <tr className="row opens" onClick={opener("/target")}>
          <td data-part="plain">
            <span data-part="text">plain words</span>
          </td>
          <td data-part="linkcell">
            <Link data-part="other" to="/elsewhere">
              another
            </Link>
          </td>
          <td>
            <a data-part="raw" href="#raw">
              raw
            </a>
          </td>
          <td data-part="actcell">
            <button type="button" data-part="act">
              Act
            </button>
          </td>
          <td data-part="pickcell">
            <input
              type="checkbox"
              data-part="pick"
              aria-label="Pick"
              checked={picked}
              onChange={(event) => setPicked(event.target.checked)}
            />
          </td>
        </tr>
      </tbody>
    </table>
  );
}

function click(selector: string, init: MouseEventInit = {}) {
  const target = mount.host().querySelector(selector);
  if (!target) throw new Error(`nothing matches ${selector}`);
  act(() => {
    target.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, ...init }));
  });
}

describe("a row that opens its target", () => {
  it("opens the target on a click in a cell that holds no control", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=text]");
    expect(location()).toBe("/target");
  });

  it("leaves a second link in the row to go where it says", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=other]");
    expect(location()).toBe("/elsewhere");
  });

  it("leaves a plain link in the row to the link", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=raw]");
    expect(location()).toBe("/list");
  });

  it("opens the target on a click beside the link in its cell", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=linkcell]");
    expect(location()).toBe("/target");
  });

  it("opens the target on a click that misses a button in its cell", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=actcell]");
    expect(location()).toBe("/target");
  });

  it("keeps the selection on a click that misses a checkbox in its cell", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=pick]");
    click("[data-part=pickcell]");
    expect(location()).toBe("/list");
    expect(mount.host().querySelector<HTMLInputElement>("[data-part=pick]")?.checked).toBe(true);
  });

  it("leaves a click on a button or a checkbox to that control", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=act]");
    click("[data-part=pick]");
    expect(location()).toBe("/list");
    expect(mount.host().querySelector<HTMLInputElement>("[data-part=pick]")?.checked).toBe(true);
  });

  it("leaves a modified or middle click to the browser", () => {
    mount.render(screen(<Row />, "/list"));
    click("[data-part=text]", { ctrlKey: true });
    click("[data-part=text]", { metaKey: true });
    click("[data-part=text]", { shiftKey: true });
    click("[data-part=text]", { button: 1 });
    expect(location()).toBe("/list");
  });

  it("does not open on the click that ends selecting text", () => {
    mount.render(screen(<Row />, "/list"));
    const text = mount.host().querySelector("[data-part=text]");
    const range = document.createRange();
    range.selectNodeContents(text!);
    window.getSelection()?.addRange(range);
    click("[data-part=text]");
    expect(location()).toBe("/list");
  });
});
