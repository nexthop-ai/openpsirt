// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { AnalysisRuns, Documents } from "./UploadLists";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("a supplier advisory", () => {
  it("fetched by a feed names the feed and links nowhere", async () => {
    serve(() => ({
      data: {
        total: 2,
        items: [
          {
            publisher: "example",
            identifier: "DSA-2",
            document: "https://example.test/csaf/dsa-2.json",
            fetched: true,
            digest: "aa",
            standing: 3,
            set_aside: 0,
            first_received_at: "2026-10-01T00:00:00Z",
            changed_at: "2026-10-02T00:00:00Z",
          },
          {
            publisher: "example",
            identifier: "DSA-1",
            document: "dsa-1.json",
            digest: "bb",
            standing: 1,
            set_aside: 2,
            first_received_at: "2026-09-01T00:00:00Z",
            changed_at: "2026-09-02T00:00:00Z",
          },
        ],
      },
    }));
    mount.render(screen(<Documents product="sonic" type="supplier-advisory" />));
    await settle();
    const rows = Array.from(mount.host().querySelectorAll("tbody tr"));
    expect(rows.map((row) => row.querySelectorAll("td")[2]?.textContent)).toEqual([
      "From a feed",
      "dsa-1.json",
    ]);
    expect(mount.host().querySelector("tbody a")).toBeNull();
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
    mount.render(screen(<AnalysisRuns build={{ product: "p", stream: "s", variant: "v" }} />));
    await settle();
    const alert = mount.host().querySelector(".alert")?.textContent ?? "";
    expect(alert).toContain("nightly");
    expect(alert).toContain("it names no commit");
  });
});
