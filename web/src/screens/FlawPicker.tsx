// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ReactNode, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useCatalog } from "../api/catalog";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { notACredential } from "../ui/noautofill";
import { nameable } from "./advisory";

// Picking a flaw an advisory may name: a product, then one of the flaws
// recorded in it, open or fixed, since an advisory is usually written after
// the fix lands.
//
// Typed as well as picked. The list is what this deployment has recorded in
// that product, and an identifier that is not in it — because the read failed,
// or because it sits past where the list stops — is still what the server
// decides about.
//
// Shared by the two places a flaw is named: starting an advisory, and adding
// one to an advisory already started.
export function FlawPicker({
  product,
  onProduct,
  flaw,
  onFlaw,
  covers = [],
  action,
}: {
  product: string;
  onProduct: (next: string) => void;
  flaw: string;
  onFlaw: (next: string) => void;
  // What the advisory already names, which is left out of what is offered.
  covers?: readonly { product?: string; vulnerability?: string }[];
  // The control that acts on the pick, drawn in the same row.
  action: ReactNode;
}) {
  const catalog = useCatalog(true);
  const recorded = useQuery({
    enabled: product !== "",
    queryKey: ["advisory-flaws", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/nameable-flaws", {
          params: { path: { product } },
        }),
      ),
  });
  const offered = useMemo(
    () => nameable(recorded.data?.items ?? [], covers, product),
    [recorded.data, covers, product],
  );

  return (
    <>
      <div className="filters" style={{ marginTop: 10 }}>
        <label className="field">
          <span>Product</span>
          <select value={product} onChange={(event) => onProduct(event.target.value)}>
            {/* A read that failed says so in the one place somebody is
                looking. A select holding nothing but "Pick a product" reads
                as a deployment with no products in it. */}
            <option value="">
              {catalog.products.isError ? "The products could not be read" : "Pick a product"}
            </option>
            {(catalog.products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name}>
                {each.display_name || each.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field" style={{ flex: 1, minWidth: 220 }}>
          <span>Flaw</span>
          <input
            type="text"
            list="advisory-flaws"
            value={flaw}
            placeholder="SONIC-2026-481907"
            onChange={(event) => onFlaw(event.target.value)}
            {...notACredential}
          />
          <datalist id="advisory-flaws">
            {offered.map((each) => (
              <option key={each.vulnerability} value={each.vulnerability}>
                {each.fixed ? `Fixed · ${each.summary}` : each.summary}
              </option>
            ))}
          </datalist>
        </label>
        {action}
      </div>
      {/* The read stops at the endpoint's own maximum, and a truncated list
          reads as the whole of what is recorded there. Typing reaches the
          rest. */}
      {(recorded.data?.total ?? 0) > (recorded.data?.items ?? []).length && (
        <p className="hint">
          More is recorded in that product than this list holds. Type the identifier in full.
        </p>
      )}
      {/* A failed read is not an answer about what is recorded here. Drawn as
          an empty list it reads as "this product has none", which is the one
          thing the read did not say. */}
      {catalog.products.isError && (
        <Failed
          error={catalog.products.error}
          what="The products could not be read, so there is none to pick."
        />
      )}
      {recorded.isError && (
        <Failed
          error={recorded.error}
          what="What is recorded in that product could not be read, so there is nothing to pick from. An identifier typed in full still works."
        />
      )}
      {product !== "" && recorded.isSuccess && offered.length === 0 && (
        <p className="hint">Nothing recorded in that product is left to name.</p>
      )}
    </>
  );
}
