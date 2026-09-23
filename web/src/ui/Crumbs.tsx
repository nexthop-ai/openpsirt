// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";

// The place you are in, and the way back up. The findings list is bound to one
// build
// , so which build that is has to be on the screen rather than only in the
// address bar.
export function Crumbs({
  product,
  stream,
  variant,
}: {
  product: string;
  stream?: string;
  variant?: string;
}) {
  const at = `/products/${encodeURIComponent(product)}`;
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
        <Link to={`${at}/streams`} className="hover:text-[var(--ink)]">
          {product}
        </Link>
      ) : (
        <span className="text-[var(--ink)]">{product}</span>
      )}
      {stream && (
        <>
          <span aria-hidden>/</span>
          {variant ? (
            <Link
              to={`${at}/streams/${encodeURIComponent(stream)}`}
              className="hover:text-[var(--ink)]"
            >
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
