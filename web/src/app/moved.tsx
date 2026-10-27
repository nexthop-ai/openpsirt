// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Navigate, useLocation, useParams, type Params } from "react-router-dom";

// Moved forwards a former address to where its screen is now, carrying the
// query and the fragment it arrived with. Replaced rather than pushed, so Back
// does not land on the former address and forward again.
export function Moved({ to }: { to: (at: Readonly<Params>) => string }) {
  const at = useParams();
  const { search, hash } = useLocation();
  return <Navigate to={to(at) + search + hash} replace />;
}

// MovedUnder forwards every address under a former prefix, handing on what
// follows the prefix as the address spelled it, still escaped. The prefix is
// the first four segments: the product, and the word after it.
export function MovedUnder({ to }: { to: (at: Readonly<Params>, rest: string) => string }) {
  const at = useParams();
  const { pathname, search, hash } = useLocation();
  const rest = pathname.split("/").slice(4).join("/");
  return <Navigate to={to(at, rest) + search + hash} replace />;
}

// The build a former address under one names.
export function built(at: Readonly<Params>) {
  return {
    product: at.product ?? "",
    branch_or_tag: at.branch_or_tag ?? "",
    variant: at.variant ?? "",
  };
}
