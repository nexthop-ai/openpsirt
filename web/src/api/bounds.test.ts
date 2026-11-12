// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { apiDocument, bodyMaxItems, queryMaximum } from "../../scripts/api-document.mjs";
import { ISSUE_MOST } from "./issue";
import { NAMED_AT_ONCE } from "../screens/findingsHandover";

// The generated client keeps no bound, so each the interface stops at is held
// to the published document here.
describe("a bound the interface stops at", () => {
  const document = apiDocument();

  it("names as many rows in one assignment as the server takes", () => {
    const most = bodyMaxItems(document, "assign-matching-findings", "only");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(NAMED_AT_ONCE).toBe(most);
  });

  it("asks for an issue's whole answer in the largest page the server gives", () => {
    const most = queryMaximum(document, "get-issue", "limit");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(ISSUE_MOST).toBe(most);
  });
});
