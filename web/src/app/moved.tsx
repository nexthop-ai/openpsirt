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

// The build a former address under one names.
export function built(at: Readonly<Params>) {
  return { product: at.product ?? "", stream: at.stream ?? "", variant: at.variant ?? "" };
}
