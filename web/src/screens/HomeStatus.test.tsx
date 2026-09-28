// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Home } from "./Home";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

describe("the front page's coverage figure", () => {
  it("counts what the coverage report counts under the same name", async () => {
    // Two out of use, one out of support, one declared and never scanned,
    // one gone quiet, six scanned: six of eight are being scanned.
    serve((path) => {
      if (path === "/v1/scanning") {
        return {
          data: {
            items: [],
            total: 11,
            unsupported: 1,
            retired: 2,
            quiet: 1,
            scanned: 6,
            quiet_after_days: 7,
          },
        };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(
      screen(
        <Home who={{ identity: "ana", name: "Ana", admin: false, kind: "person", reach: [] }} />,
      ),
    );
    await settle();
    const row = Array.from(mount.host().querySelectorAll("li")).find(
      (each) => each.querySelector(".what")?.textContent === "Builds being scanned",
    );
    expect(row?.querySelector(".when")?.textContent).toBe("6 of 8");
  });
});
