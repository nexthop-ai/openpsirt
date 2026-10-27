// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { Moved, MovedUnder, built } from "./moved";
import {
  ROUTES,
  bulkDecisionAt,
  decisionAt,
  fromStreamsAt,
  inventoryChangesAt,
  personAt,
} from "./routes";

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
        "/products/sonic/branches-and-tags/main/variants/broadcom/scans/7/changes",
        ROUTES.formerInventoryChanges,
        (at) => inventoryChangesAt(built(at), Number(at.sbom)),
      ),
    ).toBe("/products/sonic/branches-and-tags/main/variants/broadcom/uploads/7/changes");
  });

  it("carries everything under a former prefix, still escaped", () => {
    mount.render(
      <MemoryRouter initialEntries={["/products/sonic/streams/a%2Fb/variants/v/findings?q=x"]}>
        <Routes>
          <Route
            path={ROUTES.formerStreams}
            element={<MovedUnder to={(at, rest) => fromStreamsAt(at.product ?? "", rest)} />}
          />
          <Route path="*" element={<Here />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(mount.host().querySelector("#here")?.textContent).toBe(
      "/products/sonic/branches-and-tags/a%2Fb/variants/v/findings?q=x",
    );
  });

  it("forwards a former prefix alone to the list it named", () => {
    mount.render(
      <MemoryRouter initialEntries={["/products/sonic/streams"]}>
        <Routes>
          <Route
            path={ROUTES.formerStreams}
            element={<MovedUnder to={(at, rest) => fromStreamsAt(at.product ?? "", rest)} />}
          />
          <Route path="*" element={<Here />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(mount.host().querySelector("#here")?.textContent).toBe(
      "/products/sonic/branches-and-tags",
    );
  });

  it("forwards a claim to the decision it is now", () => {
    expect(
      landing("/claims/12#approve", ROUTES.formerDecision, (at) => decisionAt(Number(at.id))),
    ).toBe("/decisions/12#approve");
  });

  it("forwards deciding about a component to the bulk decision, with what it narrowed by", () => {
    expect(
      landing(
        "/products/sonic/branches-and-tags/main/variants/broadcom/components/libfoo/decide?version=1.2",
        ROUTES.formerBulkDecision,
        (at) => bulkDecisionAt(built(at), at.component ?? ""),
      ),
    ).toBe(
      "/products/sonic/branches-and-tags/main/variants/broadcom/components/libfoo/bulk-decision?version=1.2",
    );
  });
});
