// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Weaknesses as Named } from "./Weakness";
import { Weaknesses as Picker } from "./Weaknesses";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const LONG =
  "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')";

describe("the kinds of flaw on a finding", () => {
  it("draws the short name where there is one and the catalog's otherwise, whole", () => {
    mount.render(
      screen(
        <Named
          of={[
            { id: "CWE-119", name: "Improper Restriction of Operations", short: "Buffer overflow" },
            { id: "CWE-1321", name: LONG },
            { id: "NVD-CWE-OTHER" },
          ]}
        />,
      ),
    );
    const names = Array.from(mount.host().querySelectorAll("li .hint"));
    expect(names.map((each) => each.textContent)).toEqual(["Buffer overflow", LONG]);
    // The catalog's name on hover, on both.
    expect(names.map((each) => each.getAttribute("title"))).toEqual([
      "Improper Restriction of Operations",
      LONG,
    ]);
    // A feed's word for no classification is not drawn as one.
    expect(mount.host().textContent).not.toContain("NVD-CWE-OTHER");
  });
});

describe("the picker on the record-a-flaw form", () => {
  it("offers what the server finds for what is typed, and names what is chosen", async () => {
    const searched: string[] = [];
    serve((path, init) => {
      if (path !== "/v1/weaknesses") return undefined;
      const query = (init as { params: { query: { q?: string; id?: string[] } } }).params.query;
      if (query.id) {
        return { data: { items: [{ id: "CWE-415", name: "Double Free", short: "Double free" }] } };
      }
      searched.push(query.q ?? "");
      return {
        data: {
          items: query.q ? [{ id: "CWE-415", name: "Double Free", short: "Double free" }] : [],
        },
      };
    });
    mount.render(screen(<Picker chosen={["CWE-415"]} onChange={() => {}} />));
    await settle();

    const input = mount.host().querySelector("input")!;
    act(() => {
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
      set.call(input, "double");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await settle();

    expect(searched).toContain("double");
    const offered = Array.from(mount.host().querySelectorAll("datalist option"));
    expect(offered.map((each) => each.getAttribute("value"))).toEqual(["CWE-415"]);
    const chosen = mount.host().querySelector("li .hint");
    expect(chosen?.textContent).toBe("Double free");
    expect(chosen?.getAttribute("title")).toBe("Double Free");
  });
});
