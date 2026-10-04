// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { Exploited, ExploitedHere } from "./Severity";

const mount = mounted();

const badge = () => mount.host().querySelector("span");

describe("the two exploitation badges", () => {
  it("names the feed's flag as known exploited and says it is not an attack here", () => {
    mount.render(<Exploited when />);
    expect(badge()?.textContent).toBe("Known exploited");
    expect(badge()?.title).toContain("Not, on its own, a sign this product was attacked");
  });

  it("draws the feed's flag without the fill the record takes", () => {
    mount.render(<Exploited when />);
    expect(badge()?.classList.contains("here")).toBe(false);
  });

  it("draws a record of being exploited here with the fill", () => {
    mount.render(<ExploitedHere when />);
    expect(badge()?.textContent).toBe("Exploited here");
    expect(badge()?.classList.contains("here")).toBe(true);
  });

  it("draws neither where the fact is absent", () => {
    mount.render(
      <>
        <Exploited when={false} />
        <ExploitedHere />
      </>,
    );
    expect(mount.host().textContent).toBe("");
  });
});
