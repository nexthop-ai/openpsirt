// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Crumbs } from "./Crumbs";
import { mounted, screen } from "../test/mount";

const mount = mounted();

const links = () =>
  [...mount.host().querySelectorAll("nav a")].map((each) => [
    each.textContent,
    each.getAttribute("href"),
  ]);

describe("the breadcrumb", () => {
  it("opens the product page from the product, where every build is named", () => {
    mount.render(screen(<Crumbs product="sonic" branch_or_tag="main" variant="x86" />));
    expect(links()).toContainEqual(["sonic", "/products/sonic"]);
  });

  it("opens the product page from a screen of the product alone", () => {
    mount.render(screen(<Crumbs product="sonic" />));
    expect(links()).toContainEqual(["sonic", "/products/sonic"]);
  });

  it("opens the branch or tag's own page from it on a build's screen", () => {
    mount.render(screen(<Crumbs product="sonic" branch_or_tag="main" variant="x86" />));
    expect(links()).toContainEqual(["main", "/products/sonic/branches-and-tags/main"]);
  });
});
