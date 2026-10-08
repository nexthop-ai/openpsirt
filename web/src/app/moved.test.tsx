// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { Moved, built } from "./moved";
import { ROUTES, inventoryChangesAt, personAt } from "./routes";

const mount = mounted();

function Here() {
  const { pathname, search, hash } = useLocation();
  return <p id="here">{pathname + search + hash}</p>;
}

function landing(from: string, path: string, to: Parameters<typeof Moved>[0]["to"]) {
  mount.render(
    <MemoryRouter initialEntries={[from]}>
      <Routes>
        <Route path={path} element={<Moved to={to} />} />
        <Route path="*" element={<Here />} />
      </Routes>
    </MemoryRouter>,
  );
  return mount.host().querySelector("#here")?.textContent;
}

describe("a former address", () => {
  it("forwards with its query and fragment", () => {
    expect(
      landing("/work?tab=people&person=alice#top", ROUTES.formerAssignments, () => "/assignments"),
    ).toBe("/assignments?tab=people&person=alice#top");
  });

  it("carries the parts of its path, escaped again for the new one", () => {
    expect(landing("/people/a%2Fb", ROUTES.formerPerson, (at) => personAt(at.identity ?? ""))).toBe(
      "/access/a%2Fb",
    );
  });

  it("carries a build, and the upload under it", () => {
    expect(
      landing(
        "/products/sonic/streams/main/variants/broadcom/scans/7/changes",
        ROUTES.formerInventoryChanges,
        (at) => inventoryChangesAt(built(at), Number(at.scan)),
      ),
    ).toBe("/products/sonic/streams/main/variants/broadcom/inventories/7/changes");
  });
});
