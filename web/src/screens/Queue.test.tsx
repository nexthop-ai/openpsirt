// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { Queue } from "./Queue";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("the review queue", () => {
  it("says the disclosure requests could not be read when their read fails", async () => {
    serve((path) =>
      path === "/v1/disclosure-movements" ? { status: 503 } : { data: { items: [], total: 0 } },
    );
    mount.render(screen(<Queue />, "/review-queue"));
    await settle();
    expect(mount.host().textContent).toContain(
      "Requests to move a disclosure date could not be read.",
    );
  });
});
