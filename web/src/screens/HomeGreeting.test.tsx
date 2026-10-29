// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Home } from "./Home";
import type { Who } from "../app/session";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

describe("the front page's greeting", () => {
  it("says somebody who triages security testing work alone holds triage", async () => {
    serve(() => ({ data: { items: [], total: 0 } }));
    mount.render(
      screen(
        <Home
          who={{
            identity: "ana",
            name: "Ana",
            admin: false,
            kind: "person",
            reach: [
              {
                product: "sonic",
                may_see: true,
                may_triage: false,
                triages_security_testing: true,
              },
            ] as unknown as Who["reach"],
            outcomes: [],
          }}
        />,
      ),
    );
    await settle();
    const text = mount.host().textContent ?? "";
    expect(text).toContain("You hold triage on sonic");
    expect(text).not.toContain("You can read");
  });
});
