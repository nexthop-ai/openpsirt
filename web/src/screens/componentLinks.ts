// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";

type Build = Body<"PerBuildBody">;

// The findings list names binaries, so a source package is every binary of it.
export const findingsAt = (product: string, row: Build, names: string[]) =>
  `/products/${encodeURIComponent(product)}` +
  `/streams/${encodeURIComponent(row.stream ?? "")}` +
  `/variants/${encodeURIComponent(row.variant ?? "")}/findings?` +
  names.map((name) => `component=${encodeURIComponent(name)}`).join("&");

export const binaries = (row: Build) => (row.packages ?? []).map((each) => each.name);

// The page's own action: the issues open on the whole source package, in the
// findings list. Absent where nothing is open, because a button leading to an
// empty list is a question answered by clicking.
export function openIssues(product: string, row: Build): { label: string; to: string } | undefined {
  const count = row.issues ?? 0;
  if (count <= 0) return undefined;
  return {
    label: `${count.toLocaleString()} open ${count === 1 ? "issue" : "issues"} →`,
    to: findingsAt(product, row, binaries(row)),
  };
}
