// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { answeredAt, holding } from "../app/families";
import { componentAt, componentSearchAt } from "../app/routes";
import { findingsPath, scopeQuery, useScope } from "../app/scope";
import { useWho } from "../app/session";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { HeldCell } from "../ui/HeldLine";
import { Loading } from "../ui/Loading";
import { notACredential } from "../ui/noautofill";
import { useReseed } from "../ui/reseed";
import { Wide } from "../ui/Wide";

// The components a term names, for a search no issue answers and for the
// rail's Components entry. Each is a source package in one product with what
// is open on it in both families, and opens the component screen, where both
// families meet. Reached with no term, it asks for one.
//
// The scope is the picker's, so changing it answers the same term again.
export function Components() {
  const { term = "" } = useParams();
  const navigate = useNavigate();
  const [typed, setTyped] = useState(term);
  // Another term in the address, from the bar's search or Back, is the box's.
  useReseed(term, () => setTyped(term));
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
  const asked = term.trim() !== "";

  return (
    <div>
      <div className="screen-head">
        <h2>{asked ? `Components named “${term}”` : "Components"}</h2>
        <p>
          {at.product ? `In ${at.product}` : "In every product you read"}
          {asked && (
            <>
              {" · "}
              <Link to={findingsPath(at, false, { q: term })}>
                Search the findings list instead
              </Link>
            </>
          )}
        </p>
      </div>
      <form
        className="filters"
        style={{ marginBottom: 10 }}
        onSubmit={(event) => {
          event.preventDefault();
          const name = typed.trim();
          if (name !== "") navigate(componentSearchAt(name));
        }}
      >
        <input
          {...notACredential}
          type="search"
          value={typed}
          onChange={(event) => setTyped(event.target.value)}
          placeholder="Part of a component’s name"
          aria-label="Part of a component’s name"
          style={{ width: 260 }}
        />
        <button type="submit" className="btn">
          Find
        </button>
      </form>
      {!asked ? (
        <Empty
          title="Type part of a component’s name."
          detail="Each match opens its component, with both families’ findings on it."
        />
      ) : found.isPending ? (
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
                    {/* A count the server left out is a family the reader
                        does not read in that product, never a zero. */}
                    <HeldCell
                      at={answeredAt(
                        holding(who.data, "dependency", row.product),
                        row.issues !== undefined,
                        row.product,
                      )}
                    >
                      {row.issues?.toLocaleString()}
                    </HeldCell>
                    <HeldCell
                      at={answeredAt(
                        holding(who.data, "code", row.product),
                        row.code_findings !== undefined,
                        row.product,
                      )}
                    >
                      {row.code_findings?.toLocaleString()}
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
