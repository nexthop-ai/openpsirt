// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { unwrap } from "./queries";
import { buildKey } from "../ui/builds";

// Where one issue sits in every product, as the issue screen reads it.
const ISSUE_PAGE = 200;

export function useIssue(vulnerability: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability],
    enabled,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/issues/{issue}", {
          params: { path: { issue: vulnerability }, query: { limit: ISSUE_PAGE } },
        }),
      ),
    retry: false,
  });
}

// The largest page the issue endpoint answers.
export const ISSUE_MOST = 500;

// The most builds one write of an issue's affected builds names.
export const BUILDS_MOST = 200;

// Where one issue sits in one product, every row the endpoint answers: the
// affected-builds editor sends the product's whole list, so it reads the
// product's answer a page at a time until it holds every row. It stops once
// the rows name more builds than one write takes, since the editor writes
// nothing past that bound. Pages are separate reads, so a scan landing between
// two of them shifts the rows under the offset: a page whose total differs
// from the first, or that repeats a row already held, marks the answer moved,
// because a shifted page also skips a row nothing else reveals.
// One row of the issue's answer: a component at a build.
function rowKey(row: {
  branch_or_tag?: string;
  variant?: string;
  component?: string;
  version?: string;
}): string {
  return [buildKey(row), row.component ?? "", row.version ?? ""].join("\u0000");
}

export function useIssueIn(vulnerability: string, product: string, enabled = true) {
  return useQuery({
    queryKey: ["issue", vulnerability, product],
    enabled,
    queryFn: async () => {
      const ask = async (offset: number) =>
        unwrap(
          await api.GET("/v1/issues/{issue}", {
            params: {
              path: { issue: vulnerability },
              query: { product, limit: ISSUE_MOST, offset },
            },
          }),
        );
      const first = await ask(0);
      const items = [...(first.items ?? [])];
      const builds = new Set(items.map((row) => buildKey(row)));
      const seen = new Set(items.map(rowKey));
      let moved = false;
      while (items.length < first.total && builds.size <= BUILDS_MOST) {
        const page = await ask(items.length);
        const next = page.items ?? [];
        if (page.total !== first.total) moved = true;
        for (const row of next) {
          if (seen.has(rowKey(row))) moved = true;
          seen.add(rowKey(row));
          builds.add(buildKey(row));
        }
        if (next.length === 0 || moved) break;
        items.push(...next);
      }
      return { ...first, items, moved };
    },
    retry: false,
  });
}
