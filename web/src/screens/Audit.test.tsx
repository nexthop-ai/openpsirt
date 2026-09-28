// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Audit, CHANGES_MOST } from "./Audit";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

describe("the change history on the record", () => {
  it("never asks for more rows than the route answers", async () => {
    const asked: number[] = [];
    serve((path, init) => {
      if (path === "/v1/session/me") {
        return { data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] } };
      }
      if (path === "/v1/administration/changes") {
        const limit = (init as { params: { query: { limit: number } } }).params.query.limit;
        asked.push(limit);
        if (limit > CHANGES_MOST) return { status: 422 };
        const items = Array.from({ length: limit }, (_, i) => ({
          id: i + 1,
          at: "2026-09-01T00:00:00Z",
          actor: "ana",
          kind: "setting",
          subject: `s${i}`,
        }));
        return { data: { items, total: 400 } };
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Audit />, "/audit"));
    await settle();
    const more = () =>
      Array.from(mount.host().querySelectorAll("button")).find(
        (each) => each.textContent === "Show more",
      );
    for (let press = 0; press < 3 && more(); press++) {
      act(() => more()?.click());
      await settle();
    }
    expect(Math.max(...asked)).toBe(CHANGES_MOST);
    expect(more()).toBeUndefined();
    expect(mount.host().textContent).not.toContain("could not be read");
  });
});
