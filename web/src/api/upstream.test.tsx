// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { useDecline, useTrust } from "./upstream";
import { acted } from "../test/acted";
import { mounted } from "../test/mount";

const mount = mounted();

// A key dropped from one of these sets leaves a screen showing what the act
// changed as it stood before.
describe("an act on an upstream, once it lands", () => {
  it("trusting moves the product's upstream, what upstreams offer and what they said", async () => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      "PUT",
      () => useTrust("sonic").trust,
      { url: "https://example.com/vex" },
    );
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual(["upstream-offers", "upstream-said", "upstream/sonic"]);
  });

  it("stopping trusting moves the product's upstream, what upstreams offer and what they said", async () => {
    const { sent, invalidated } = await acted(
      mount.render,
      mount.host,
      "DELETE",
      () => useTrust("sonic").withdraw,
      undefined as never,
    );
    expect(sent).toHaveLength(1);
    expect(invalidated).toEqual(["upstream-offers", "upstream-said", "upstream/sonic"]);
  });

  it.each([
    ["declining", "PUT", true],
    ["taking a decline back", "DELETE", false],
  ] as const)(
    "%s a statement moves the offers, what upstreams said and the finding",
    async (_, method, declined) => {
      const { sent, invalidated } = await acted(mount.render, mount.host, method, useDecline, {
        statement: 3,
        declined,
      });
      expect(sent).toEqual([
        ["/v1/statements/{statement}/declined", { params: { path: { statement: 3 } } }],
      ]);
      expect(invalidated).toEqual(["finding", "upstream-offers", "upstream-said"]);
    },
  );
});
