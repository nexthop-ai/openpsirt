// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { KindChips, NamesMoved, type Kind } from "../ui/NamesMoved";

// The most one page asks for. Long enough that an ordinary night fits on one
// page, short enough that a build which replaced everything does not arrive as
// one screen of two thousand rows.
const PAGE = 200;

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
  const build =
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}`;

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
          <Link to={`${build}/scans`} className="linkish" style={{ fontWeight: 500 }}>
            Inventories
          </Link>{" "}
          › <b>upload {scan}</b>
        </span>
        <h2>Changes in this upload</h2>
        <p>
          {product} · {stream} · {variant} · against the upload before it
        </p>
      </div>

      <KindChips
        only={only}
        onPick={(kind) => {
          setOnly(kind);
          setOffset(0);
        }}
      />

      {items.length === 0 ? (
        /* Two different emptinesses. Narrowed to one kind, what is empty is
           the narrowing; unnarrowed, it is the upload — and the shipped
           sentence about a first upload is wrong about the first of those. */
        only ? (
          <Empty
            title={`Nothing was ${only === "changed" ? "moved to a new version" : only}.`}
            detail="This upload changed other things."
          >
            {/* The way back, because the chips that produced this are above a
                screen somebody may have scrolled. */}
            <button
              type="button"
              className="btn"
              onClick={() => {
                setOnly("");
                setOffset(0);
              }}
            >
              Show everything
            </button>
          </Empty>
        ) : (
          <Empty
            title="Nothing changed here."
            detail="A build's first upload, or a rebuild that moved nothing."
          />
        )
      ) : (
        <>
          <NamesMoved product={product} rows={items} />
          <Paged
            shown={items.length}
            total={total}
            offset={offset}
            limit={PAGE}
            onGo={setOffset}
            what="listed"
          />
        </>
      )}
    </div>
  );
}
