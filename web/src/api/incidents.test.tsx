// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { useAfterIncident } from "./incidents";
import { client, mounted, screen, watchInvalidations } from "../test/mount";
import { act } from "react";

const mount = mounted();

describe("an act on an incident", () => {
  it("moves the incidents list, which Home's tile reads, and the finding", async () => {
    const queries = client();
    const invalidated = watchInvalidations(queries);
    function Act() {
      const after = useAfterIncident();
      return (
        <button type="button" onClick={after}>
          act
        </button>
      );
    }
    mount.render(screen(<Act />, "/", "*", queries));
    await act(async () => mount.host().querySelector("button")?.click());
    expect(invalidated()).toEqual(["finding", "incidents"]);
  });
});
