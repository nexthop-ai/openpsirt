// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { MovedPage, PAGE, type Kind } from "../ui/NamesMoved";
import { inventoriesAt } from "../app/routes";

// What one upload changed about a build's inventory.
//
// The receipt says how many names moved and this says which. Removals come
// first: a build that stopped describing a dependency looks exactly like one
// that stopped shipping it, and telling those apart is somebody reading this
// page beside the build.
export function InventoryChanges() {
  const { product = "", stream = "", variant = "", scan = "" } = useParams();
  const [offset, setOffset] = useState(0);
  const [only, setOnly] = useState<Kind>("");
  const at = { product, stream, variant, scan: Number(scan) };

  const changes = useQuery({
    queryKey: ["inventory-changes", at, only, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/scans/{scan}/changes",
          {
            params: {
              path: at,
              query: { limit: PAGE, offset, ...(only ? { change: only } : {}) },
            },
          },
        ),
      ),
  });

  if (changes.isPending) return <Loading />;
  if (changes.isError)
    return <Failed error={changes.error} what="What this upload changed could not be read." />;

  const items = changes.data?.items ?? [];
  const total = changes.data?.total ?? 0;

  return (
    <div>
      <div className="screen-head">
        <span className="crumbs">
          <Link
            to={inventoriesAt({ product, stream, variant })}
            className="linkish"
            style={{ fontWeight: 500 }}
          >
            Inventories
          </Link>{" "}
          › <b>upload {scan}</b>
        </span>
        <h2>Changes in this upload</h2>
        <p>
          {product} · {stream} · {variant} · against the upload before it
        </p>
      </div>

      <MovedPage
        product={product}
        only={only}
        onPick={(kind) => {
          setOnly(kind);
          setOffset(0);
        }}
        rows={items}
        total={total}
        offset={offset}
        onGo={setOffset}
        otherwise="This upload changed other things."
        nothing={{
          title: "Nothing changed here.",
          detail: "A build's first upload, or a rebuild that moved nothing.",
        }}
      />
    </div>
  );
}
