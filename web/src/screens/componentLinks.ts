// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Body } from "../api/client";
import { buildFindingsAt, streamAt, streamsAt, upgradesAt } from "../app/routes";

type Build = Body<"PerBuildBody">;

// The findings list names binaries, so a source package is every binary of it.
export const findingsAt = (product: string, row: Build, names: string[]) =>
  buildFindingsAt(
    { product, stream: row.stream ?? "", variant: row.variant ?? "" },
    new URLSearchParams(names.map((name) => ["component", name])),
  );

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

// Where a promised upgrade is followed once it is made. Three builds or fewer
// is a link to each build's pending upgrades; more is one link to the release
// they share, or to the product's releases where they span several.
export function promiseLinks(
  product: string,
  builds: { stream: string; variant: string }[],
): { label: string; to: string }[] {
  if (builds.length <= 3) {
    return builds.map((build) => ({
      label: `Pending upgrades in ${build.stream} · ${build.variant} →`,
      to: upgradesAt({ product, ...build }),
    }));
  }
  const streams = new Set(builds.map((build) => build.stream));
  if (streams.size === 1) {
    const [stream = ""] = streams;
    return [{ label: `${stream} →`, to: streamAt(product, stream) }];
  }
  return [{ label: "Releases →", to: streamsAt(product) }];
}
