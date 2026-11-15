// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { apiDocument, bodyMaxItems, queryMaximum } from "../../scripts/api-document.mjs";
import { BUILDS_MOST, ISSUE_MOST } from "./issue";
import { NAMED_AT_ONCE } from "../screens/findingsHandover";
import { CHANGES_MOST } from "../screens/AuditLog";
import { BACK_LIMIT } from "../screens/Home";
import { LIST_MOST } from "../screens/list";
import { FURTHEST } from "../screens/analytics/Support";
import { LONGEST, MOST_DAYS, MOST_WEEKS } from "../screens/analytics/Window";

// The generated client keeps no bound, so each the interface stops at is held
// to the published document here.
describe("a bound the interface stops at", () => {
  const document = apiDocument();

  it("names as many rows in one assignment as the server takes", () => {
    const most = bodyMaxItems(document, "assign-matching-findings", "only");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(NAMED_AT_ONCE).toBe(most);
  });

  it("sets no more affected builds in one write than the server takes", () => {
    const most = bodyMaxItems(document, "set-affected-builds", "builds");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(BUILDS_MOST).toBe(most);
  });

  it("asks for an issue's whole answer in the largest page the server gives", () => {
    const most = queryMaximum(document, "get-issue", "limit");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(ISSUE_MOST).toBe(most);
  });

  it("asks a findings list for no larger page than the server gives", () => {
    for (const id of ["list-findings", "list-findings-anywhere"]) {
      const most = queryMaximum(document, id, "limit");
      expect(most, `${id} states no bound, so this checked nothing`).toBeTypeOf("number");
      expect(LIST_MOST, id).toBe(most);
    }
  });

  it("asks the change history for no larger page than the server gives", () => {
    const most = queryMaximum(document, "list-administrative-changes", "limit");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(CHANGES_MOST).toBe(most);
  });

  it("reads no more of a person's own decisions than the server gives", () => {
    const most = queryMaximum(document, "list-my-decisions", "limit");
    expect(most, "the document states no bound, so this checked nothing").toBeTypeOf("number");
    expect(BACK_LIMIT).toBe(most);
  });

  it("offers no trend window longer than the server answers", () => {
    const weeks = Object.values(document.paths).flatMap((methods) =>
      Object.values(
        methods as Record<
          string,
          { parameters?: { in: string; name: string; schema?: { maximum?: number } }[] }
        >,
      ).flatMap((operation) =>
        (operation.parameters ?? [])
          .filter((each) => each.in === "query" && each.name === "weeks")
          .map((each) => each.schema?.maximum),
      ),
    );
    expect(weeks.length, "no weeks parameter was found, so this checked nothing").toBeGreaterThan(
      0,
    );
    expect(new Set(weeks)).toEqual(new Set([MOST_WEEKS]));
    for (const id of ["get-trend", "trend-code-findings"]) {
      expect(queryMaximum(document, id, "days"), id).toBe(MOST_DAYS);
    }
  });

  it("offers no report window longer than the server answers", () => {
    for (const id of [
      "list-published-advisories",
      "get-approval-scrutiny",
      "get-measures",
      "get-remediation",
      "get-effort",
    ]) {
      expect(queryMaximum(document, id, "days"), id).toBe(LONGEST);
    }
    expect(queryMaximum(document, "list-out-of-support", "within")).toBe(FURTHEST);
  });
});
