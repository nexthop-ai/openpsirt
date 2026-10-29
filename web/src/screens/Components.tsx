// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { holding } from "../app/families";
import { componentAt } from "../app/routes";
import { findingsPath, scopeQuery, useScope } from "../app/scope";
import { useWho } from "../app/session";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { HeldCell } from "../ui/HeldLine";
import { Loading } from "../ui/Loading";
import { Wide } from "../ui/Wide";

// The components a term names, for a search no issue answers. Each is a source
// package in one product with what is open on it in both families, and opens
// the component screen, where both families meet.
//
// The scope is the picker's, so changing it answers the same term again.
export function Components() {
  const { term = "" } = useParams();
  const at = useScope();
  const who = useWho();
  const found = useQuery({
    queryKey: ["component-matches", term, scopeQuery(at)],
    enabled: term.trim() !== "",
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/components", {
          params: { query: { q: term, ...scopeQuery(at) } },
        }),
      ).items ?? [],
  });
  const rows = found.data ?? [];

  return (
    <div>
      <div className="screen-head">
        <h2>Components named “{term}”</h2>
        <p>
          {at.product ? `In ${at.product}` : "In every product you read"}
          {" · "}
          <Link to={findingsPath(at, false, { q: term })}>Search the findings list instead</Link>
        </p>
      </div>
      {found.isPending ? (
        <Loading />
      ) : found.isError ? (
        <Failed error={found.error} what="The components could not be searched." />
      ) : rows.length === 0 ? (
        <Empty
          title={`No component here is called "${term}".`}
          detail="Part of a name, ignoring case, in the builds the picker selects."
        />
      ) : (
        <div className="card">
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Product</th>
                  <th className="num" title="Distinct issues open on it">
                    Open issues
                  </th>
                  <th className="num" title="Open code findings placed on it">
                    Code findings
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.product}\u001e${row.component}`} className="row">
                    <td>
                      <Link className="id" to={componentAt(row.product, row.component)}>
                        {row.component}
                      </Link>
                    </td>
                    <td>{row.product}</td>
                    <HeldCell at={holding(who.data, "dependency", row.product)}>
                      {(row.issues ?? 0).toLocaleString()}
                    </HeldCell>
                    <HeldCell at={holding(who.data, "code", row.product)}>
                      {(row.code_findings ?? 0).toLocaleString()}
                    </HeldCell>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        </div>
      )}
    </div>
  );
}
