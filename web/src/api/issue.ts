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
// nothing past that bound. Pages are separate reads, so a change landing between
// two of them shifts the rows under the offset and a row goes unread. Each
// later page starts one row early, on the last row held: a page that opens on
// any other row, or answers another total, marks the answer moved. Rows carry
// no unique key, since two components can share a name and version, so the
// overlap is compared whole.
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
      let moved = false;
      while (items.length > 0 && items.length < first.total && builds.size <= BUILDS_MOST) {
        const page = await ask(items.length - 1);
        const [overlap, ...next] = page.items ?? [];
        if (
          page.total !== first.total ||
          JSON.stringify(overlap) !== JSON.stringify(items[items.length - 1])
        ) {
          moved = true;
          break;
        }
        if (next.length === 0) break;
        items.push(...next);
        for (const row of next) builds.add(buildKey(row));
      }
      return { ...first, items, moved };
    },
    retry: false,
  });
}
