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
import { MovedPage, PAGE, type Kind } from "../ui/NamesMoved";
import { PickPair, useBuildPair } from "../ui/PickBuild";
import { comparisonAt } from "../app/routes";

// Which names any two builds of a product differ on.
//
// Two releases, two platforms of one release, or a tag and the branch it was
// cut from. The release comparison answers what is open against each; this
// answers what each contains.
export function InventoryCompare() {
  const { product = "" } = useParams();
  const builds = useBuildPair(product);
  const { ready, pair } = builds;
  const only = (builds.params.get("change") ?? "") as Kind;
  const [offset, setOffset] = useState(0);

  const differences = useQuery({
    queryKey: ["inventory-comparison", product, pair, only, offset],
    enabled: ready,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/comparison/inventory", {
          params: {
            path: { product },
            query: { ...pair, limit: PAGE, offset, ...(only ? { change: only } : {}) },
          },
        }),
      ),
  });

  // Each choice resets the page, because a page of one comparison is not a
  // page of another.
  function set(key: string, value: string) {
    builds.set(key, value);
    setOffset(0);
  }

  // The file is the comparison on the screen, narrowing included.
  const asked = new URLSearchParams({ ...pair, ...(only ? { change: only } : {}) }).toString();
  const items = differences.data?.items ?? [];
  const total = differences.data?.total ?? 0;

  return (
    <div>
      <div className="screen-head">
        <span className="crumbs">
          <Link to={comparisonAt(product, pair)} className="linkish" style={{ fontWeight: 500 }}>
            Release comparison
          </Link>{" "}
          › <b>components</b>
        </span>
        <h2>Component comparison</h2>
        <p>{product} — the component names two builds differ on, as each stands now</p>
      </div>

      <div className="card">
        <header
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            flexWrap: "wrap",
            marginBottom: 12,
          }}
        >
          <h3 style={{ margin: 0 }}>Compare</h3>
          <PickPair builds={builds} set={set} />
          {ready && (
            <span style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
              <a
                className="btn quiet"
                href={`/v1/products/${encodeURIComponent(product)}/comparison/inventory.csv?${asked}`}
              >
                CSV
              </a>
              <a
                className="btn quiet"
                href={`/v1/products/${encodeURIComponent(product)}/comparison/inventory.json?${asked}`}
              >
                JSON
              </a>
            </span>
          )}
        </header>

        {!ready ? (
          <Empty
            title="Pick two builds."
            detail="Any two: across releases, across platforms, or a tag against its branch."
          />
        ) : (
          <MovedPage
            product={product}
            only={only}
            onPick={(kind) => set("change", kind)}
            rows={items}
            total={total}
            offset={offset}
            onGo={setOffset}
            removedIsGone={false}
            otherwise="These two differ in other ways."
            nothing={{ title: "No differences.", detail: "Both builds hold the same components." }}
            waiting={
              differences.isPending ? (
                <Loading />
              ) : differences.isError ? (
                <Failed error={differences.error} what="Those two could not be compared." />
              ) : undefined
            }
          />
        )}
      </div>
    </div>
  );
}
