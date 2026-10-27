// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { AnalysisRuns, Documents } from "./UploadLists";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("a supplier advisory", () => {
  it("names who sent it, and a feed's links nowhere", async () => {
    serve(() => ({
      data: {
        total: 3,
        items: [
          {
            received_at: "2026-10-03T00:00:00Z",
            status: "refused",
            reason: "that is not an advisory",
            publisher: "",
            document: "broken.json",
            uploaded_by: "admin@example.com",
            uploaded_by_name: "Admin",
            recorded: 0,
            set_aside: 0,
            current: false,
          },
          {
            received_at: "2026-10-02T00:00:00Z",
            status: "completed",
            publisher: "example",
            identifier: "DSA-2",
            document: "https://example.test/csaf/dsa-2.json",
            fetched_by: "Example Linux",
            digest: "aa",
            recorded: 3,
            set_aside: 0,
            current: true,
          },
          {
            received_at: "2026-09-02T00:00:00Z",
            status: "completed",
            publisher: "example",
            identifier: "DSA-1",
            document: "dsa-1.json",
            uploaded_by: "admin@example.com",
            digest: "bb",
            recorded: 1,
            set_aside: 2,
            current: false,
          },
        ],
      },
    }));
    mount.render(screen(<Documents product="sonic" type="supplier-advisory" />));
    await settle();
    const rows = Array.from(mount.host().querySelectorAll("tbody tr"));
    const cell = (n: number) => rows.map((row) => row.querySelectorAll("td")[n]?.textContent);
    expect(cell(1)).toEqual(["Admin", "Example Linux feed", "admin@example.com"]);
    expect(cell(4)).toEqual(["broken.json", "From the feed", "dsa-1.json"]);
    expect(cell(5)[0]).toContain("Refused");
    expect(cell(5)[0]).toContain("that is not an advisory");
    expect(cell(5)[1]).toContain("Current");
    expect(cell(5)[2]).not.toContain("Current");
    expect(mount.host().querySelector("tbody a")).toBeNull();
    expect(mount.host().textContent).toContain("All builds of this product");
  });
});

describe("a static analysis run", () => {
  it("turned away is said with what its sender was told", async () => {
    serve(() => ({
      data: {
        total: 0,
        items: [],
        refused: [{ series: "nightly", at: "2026-10-01T00:00:00Z", reason: "it names no commit" }],
      },
    }));
    mount.render(
      screen(<AnalysisRuns build={{ product: "p", branch_or_tag: "s", variant: "v" }} />),
    );
    await settle();
    const alert = mount.host().querySelector(".alert")?.textContent ?? "";
    expect(alert).toContain("nightly");
    expect(alert).toContain("it names no commit");
  });
});
