// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { listQuery } from "../list";
import { plainlyLate } from "./Compliance";

describe("the link under what is plainly late", () => {
  it("asks the list for what is overdue, in a word the list reads", () => {
    const path = plainlyLate({ product: "sonic", stream: "master" });
    const asked = listQuery(new URLSearchParams(path.slice(path.indexOf("?"))));
    expect(asked).toMatchObject({ overdue: true });
  });
});
