// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { branchOrTagAt, productAt } from "../app/routes";

// The place you are in, and the way back up. A screen bound to one build says
// which build that is on the screen rather than only in the address bar. The
// product opens its page, where every build is named with what is open in it.
export function Crumbs({
  product,
  branch_or_tag: branchOrTag,
  variant,
}: {
  product: string;
  branch_or_tag?: string;
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
      <Link to={productAt(product)} className="hover:text-[var(--ink)]">
        {product}
      </Link>
      {branchOrTag && (
        <>
          <span aria-hidden>/</span>
          {variant ? (
            <Link to={branchOrTagAt(product, branchOrTag)} className="hover:text-[var(--ink)]">
              {branchOrTag}
            </Link>
          ) : (
            <span className="text-[var(--ink)]">{branchOrTag}</span>
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
