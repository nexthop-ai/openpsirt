// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { streamAt, streamsAt } from "../app/routes";

// The place you are in, and the way back up. A screen bound to one build says
// which build that is on the screen rather than only in the address bar.
export function Crumbs({
  product,
  stream,
  variant,
}: {
  product: string;
  stream?: string;
  variant?: string;
}) {
  return (
    <nav
      aria-label="Breadcrumb"
      className="mb-3 flex flex-wrap items-center gap-1 text-sm text-[var(--muted)]"
    >
      <Link to="/products" className="hover:text-[var(--ink)]">
        Products
      </Link>
      <span aria-hidden>/</span>
      {stream ? (
        <Link to={streamsAt(product)} className="hover:text-[var(--ink)]">
          {product}
        </Link>
      ) : (
        <span className="text-[var(--ink)]">{product}</span>
      )}
      {stream && (
        <>
          <span aria-hidden>/</span>
          {variant ? (
            <Link to={streamAt(product, stream)} className="hover:text-[var(--ink)]">
              {stream}
            </Link>
          ) : (
            <span className="text-[var(--ink)]">{stream}</span>
          )}
        </>
      )}
      {variant && (
        <>
          <span aria-hidden>/</span>
          <span className="text-[var(--ink)]">{variant}</span>
        </>
      )}
    </nav>
  );
}
