// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { useRetireDestination } from "./outbound";
import { acted } from "../test/acted";
import { mounted } from "../test/mount";

const mount = mounted();

describe("retiring a destination, once it lands", () => {
  it("sends its name and kind and moves the one read of every destination", async () => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      "DELETE",
      useRetireDestination,
      { name: "security", kind: "slack" },
    );
    expect(sent).toEqual([
      ["/v1/outbound/{name}/{kind}", { params: { path: { name: "security", kind: "slack" } } }],
    ]);
    expect(invalidated).toEqual(["outbound"]);
  });
});
