// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { counted, holding, type Holding } from "../app/families";
import type { Who } from "../app/session";
import { codeFindingsAcrossAt, ROUTES } from "../app/routes";
import { UNOWNED, UNOWNED_LIST, asAsked, listQuery } from "./list";

// Work nobody holds, one family at a time: the dependency findings nobody
// holds and nobody has decided, and the code findings nobody holds. Each is
// its own list and its own count, never their sum.

// The dependency count, asked as the list itself asks it.
//
// The list writes three narrowings of its own into whatever address it is
// given — nothing lands in a tag, nothing in a release past end-of-life, and
// the by-issue view sets aside what a promised upgrade already answers — so a
// total counted without them is a number that disagrees with the list it
// opens. Built from the list's own address for that reason.
const UNOWNED_QUERY = listQuery(asAsked(new URLSearchParams(UNOWNED), "issues"));

// The code findings nobody holds, in every product the reader reads them in.
const UNOWNED_CODE = "assigned=nobody";
const UNOWNED_CODE_LIST = codeFindingsAcrossAt({ assigned: "nobody" });

// One family of work nobody holds: how the reader holds it, where its list
// is, the filters its address carries, and its count, asked only where the
// family is counted.
export type Unowned = {
  at: Holding;
  to: string;
  mark: string;
  count: { data?: { total?: number }; isError: boolean; isPending: boolean; error: unknown };
};

export function useUnowned(who: Who | null | undefined): { dependency: Unowned; code: Unowned } {
  const dependencies = holding(who, "dependency");
  const code = holding(who, "code");
  const dependencyCount = useQuery({
    queryKey: ["findings", "unowned"],
    enabled: counted(dependencies),
    queryFn: async () =>
      unwrap(await api.GET("/v1/findings", { params: { query: { ...UNOWNED_QUERY, limit: 1 } } })),
    refetchInterval: 60_000,
  });
  // Keyed under the code findings, so every act that moves one moves this.
  const codeCount = useQuery({
    queryKey: ["code-findings", "", "unowned"],
    enabled: counted(code),
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/code-findings", { params: { query: { assigned: "nobody", limit: 1 } } }),
      ),
    refetchInterval: 60_000,
  });
  return {
    dependency: { at: dependencies, to: UNOWNED_LIST, mark: UNOWNED, count: dependencyCount },
    code: { at: code, to: UNOWNED_CODE_LIST, mark: UNOWNED_CODE, count: codeCount },
  };
}

// Where work nobody holds opens: the screen offering both lists where the
// reader counts both families, and the one list straight away where they
// count one.
export function unownedAt(unowned: { dependency: Unowned; code: Unowned }): {
  to: string;
  mark?: string;
} {
  const dependency = counted(unowned.dependency.at);
  const code = counted(unowned.code.at);
  if (dependency && code) return { to: ROUTES.unassigned };
  if (code) return { to: unowned.code.to, mark: unowned.code.mark };
  return { to: unowned.dependency.to, mark: unowned.dependency.mark };
}
