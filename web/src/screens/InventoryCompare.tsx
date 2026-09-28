// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { KindChips, NamesMoved, type Kind } from "../ui/NamesMoved";
import { Paged } from "../ui/Paged";
import { PickBuild } from "../ui/PickBuild";

// The most one page asks for, as on one upload's listing.
const PAGE = 200;

// Which names any two builds of a product differ on.
//
// Two releases, two platforms of one release, or a tag and the branch it was
// cut from. The release comparison answers what is open against each; this
// answers what each contains.
export function InventoryCompare() {
  const { product = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const from = params.get("from") ?? "";
  const fromVariant = params.get("from_variant") ?? "";
  const to = params.get("to") ?? "";
  const toVariant = params.get("to_variant") ?? "";
  const only = (params.get("change") ?? "") as Kind;
  const [offset, setOffset] = useState(0);

  const streams = useQuery({
    queryKey: ["streams", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });
  const variants = useQuery({
    queryKey: ["variants", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/variants", { params: { path: { product } } })),
  });

  const ready = from !== "" && fromVariant !== "" && to !== "" && toVariant !== "";
  const pair = { from, from_variant: fromVariant, to, to_variant: toVariant };
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
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
    setOffset(0);
  }

  // The file is the comparison on the screen, narrowing included.
  const asked = new URLSearchParams({ ...pair, ...(only ? { change: only } : {}) }).toString();
  const streamNames = (streams.data?.items ?? []).map((each) => each.name ?? "");
  const variantNames = (variants.data?.items ?? []).map((each) => each.name ?? "");
  const items = differences.data?.items ?? [];
  const total = differences.data?.total ?? 0;

  return (
    <div>
      <div className="screen-head">
        <span className="crumbs">
          <Link
            to={`/products/${encodeURIComponent(product)}/comparison?${new URLSearchParams(pair)}`}
            className="linkish"
            style={{ fontWeight: 500 }}
          >
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
          {(streams.isError || variants.isError) && (
            <Failed
              error={streams.isError ? streams.error : variants.error}
              what="The builds to compare could not be read."
            />
          )}
          <PickBuild
            label="Earlier build"
            stream={from}
            variant={fromVariant}
            streams={streamNames}
            variants={variantNames}
            onStream={(value) => set("from", value)}
            onVariant={(value) => set("from_variant", value)}
          />
          <span style={{ color: "var(--faint)" }}>to</span>
          <PickBuild
            label="Later build"
            stream={to}
            variant={toVariant}
            streams={streamNames}
            variants={variantNames}
            onStream={(value) => set("to", value)}
            onVariant={(value) => set("to_variant", value)}
          />
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
          <>
            <KindChips only={only} onPick={(kind) => set("change", kind)} />
            {differences.isPending ? (
              <Loading />
            ) : differences.isError ? (
              <Failed error={differences.error} what="Those two could not be compared." />
            ) : items.length === 0 ? (
              only ? (
                <Empty
                  title={`Nothing was ${only === "changed" ? "moved to a new version" : only}.`}
                  detail="These two differ in other ways."
                >
                  <button type="button" className="btn" onClick={() => set("change", "")}>
                    Show everything
                  </button>
                </Empty>
              ) : (
                <Empty title="No differences." detail="Both builds hold the same components." />
              )
            ) : (
              <>
                <NamesMoved product={product} rows={items} removedIsGone={false} />
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
          </>
        )}
      </div>
    </div>
  );
}
