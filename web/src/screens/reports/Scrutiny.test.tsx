// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Scrutiny } from "./Scrutiny";
import { PUBLISHED } from "../../test/outcomes";
import { mounted, screen, serve, settle } from "../../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("risk standing on one person", () => {
  it("files a lead's dismissal standing alone as a control that did not hold", async () => {
    serve((path) => {
      if (path === "/v1/session/me") {
        return {
          data: {
            identity: "ana",
            name: "Ana",
            admin: true,
            kind: "person",
            reach: [],
            outcomes: PUBLISHED,
          },
        };
      }
      if (path === "/v1/approvals/scrutiny") {
        return {
          data: {
            alone: [
              { outcome: "dismissed", decisions: 1, rows: 1 },
              { outcome: "not-security", decisions: 1, rows: 1 },
              { outcome: "deferred", decisions: 2, rows: 2 },
            ],
            agreed: 0,
            pairs: [],
            bulk: [],
            grew: [],
            lapsed: [],
          },
        };
      }
      return undefined;
    });
    mount.render(screen(<Scrutiny />, "/reports/scrutiny"));
    await settle();
    // The failed half links each outcome to the audit log; the exceptions do not.
    const failed = Array.from(mount.host().querySelectorAll("a"))
      .filter((each) => each.textContent === "Decisions →")
      .map((each) =>
        new URL(each.getAttribute("href") ?? "", "http://x").searchParams.get("outcome"),
      );
    expect(failed.sort()).toEqual(["dismissed", "not-security"]);
  });
});
