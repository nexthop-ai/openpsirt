// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Crumbs } from "../ui/Crumbs";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";

const PAGE = 200;

// Each reason's label, and what fixes it on hover.
const REASONS: Record<string, { label: string; fix: string }> = {
  "no-identifier": {
    label: "No package identifier",
    fix: "No purl. A CPE on its own matches nothing.",
  },
  "unpublished-kind": {
    label: "Nothing published for this kind",
    fix: "No vulnerability data exists for container images or source repositories.",
  },
  "no-version": {
    label: "No version",
    fix: "Missing, or written as UNKNOWN or (devel).",
  },
  "no-distribution": {
    label: "No distribution",
    fix: "A deb, rpm or apk purl without distro=, so the distribution's advisories can't be picked.",
  },
  "generic-without-cpe": {
    label: "Generic, no CPE",
    fix: "pkg:generic names no ecosystem, so only a CPE can match it.",
  },
};

// What a build holds that the scanner has no way to match, by reason.
//
// Such a component reports no findings, which is also what a clean one
// reports. The tree's header counts them and links here.
export function MatchCoverage() {
  const { product = "", stream = "", variant = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const reason = params.get("reason") ?? "";
  const [offset, setOffset] = useState(0);
  const coverage = useQuery({
    queryKey: ["match-coverage", product, stream, variant, reason, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/match-coverage", {
          params: {
            path: { product, stream, variant },
            query: {
              ...(reason ? { reason: reason as never } : {}),
              limit: PAGE,
              offset,
            },
          },
        }),
      ),
  });

  const pick = (next: string) => {
    setOffset(0);
    setParams(next ? { reason: next } : {});
  };

  if (coverage.isPending) return <Loading />;
  if (coverage.isError) {
    return <Failed error={coverage.error} what="The unmatched components could not be read." />;
  }
  const data = coverage.data;
  const items = data.items ?? [];

  return (
    <>
      <Crumbs product={product} stream={stream} variant={variant} />
      <div className="screen-head">
        <h2>
          Unmatched components <span className="n">{data.unmatched.toLocaleString()}</span>
        </h2>
        <p>
          {stream} · {variant} — {data.unmatched.toLocaleString()} of{" "}
          {data.components.toLocaleString()} components can't be matched, so they report no
          findings.
        </p>
      </div>

      {data.unmatched === 0 ? (
        <Empty title="The scanner can match every component in this build." />
      ) : (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <button
              type="button"
              className="chip"
              aria-pressed={reason === ""}
              onClick={() => pick("")}
            >
              All {data.unmatched.toLocaleString()}
            </button>
            {(data.reasons ?? [])
              .filter((one) => one.count > 0)
              .map((one) => (
                <button
                  key={one.reason}
                  type="button"
                  className="chip"
                  aria-pressed={reason === one.reason}
                  title={REASONS[one.reason]?.fix}
                  onClick={() => pick(one.reason)}
                >
                  {REASONS[one.reason]?.label ?? one.reason} {one.count.toLocaleString()}
                </button>
              ))}
          </div>

          <p className="hint">
            Download <a href={fileAt(product, stream, variant, "csv", reason)}>CSV</a> ·{" "}
            <a href={fileAt(product, stream, variant, "json", reason)}>JSON</a>.
          </p>

          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Version</th>
                  <th>Identifier</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr
                    key={`${row.reason}\u0000${row.purl ?? ""}\u0000${row.name}\u0000${row.version}`}
                  >
                    <td>
                      <Link
                        to={`/products/${encodeURIComponent(product)}/components/${encodeURIComponent(row.name)}`}
                        className="linkish"
                      >
                        {row.name}
                      </Link>
                    </td>
                    <td className="id">{row.version || "—"}</td>
                    <td className="id hint">{row.purl || row.cpe || "—"}</td>
                    <td title={REASONS[row.reason]?.fix}>
                      {REASONS[row.reason]?.label ?? row.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
          <Paged
            shown={items.length}
            total={data.total}
            offset={offset}
            limit={PAGE}
            onGo={setOffset}
          />
        </>
      )}
    </>
  );
}

// The address the file comes from.
function fileAt(
  product: string,
  stream: string,
  variant: string,
  format: string,
  reason: string,
): string {
  return (
    `/v1/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}/match-coverage.${format}` +
    (reason ? `?reason=${encodeURIComponent(reason)}` : "")
  );
}
