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
import { uploadsAt } from "../app/routes";

// What one upload changed about a build's inventory.
//
// The receipt says how many names moved and this says which. Removals come
// first: a build that stopped describing a dependency looks exactly like one
// that stopped shipping it, and telling those apart is somebody reading this
// page beside the build.
export function InventoryChanges() {
  const {
    product = "",
    branch_or_tag: branchOrTag = "",
    variant = "",
    sbom: scan = "",
  } = useParams();
  const [offset, setOffset] = useState(0);
  const [only, setOnly] = useState<Kind>("");
  const at = { product, branch_or_tag: branchOrTag, variant, scan: Number(scan) };

  const changes = useQuery({
    queryKey: ["inventory-changes", at, only, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/sboms/{sbom}/changes",
          {
            params: {
              path: { product, branch_or_tag: branchOrTag, variant, sbom: at.scan },
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
            to={uploadsAt({ product, branch_or_tag: branchOrTag, variant })}
            className="linkish"
            style={{ fontWeight: 500 }}
          >
            Uploads
          </Link>{" "}
          › <b>upload {scan}</b>
        </span>
        <h2>Changes in this upload</h2>
        <p>
          {product} · {branchOrTag} · {variant} · against the upload before it
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
