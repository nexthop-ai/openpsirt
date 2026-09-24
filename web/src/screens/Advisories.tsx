// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { PAGE, useAdvisories, useAfterAdvisory } from "../api/advisories";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { AddButton } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { standing, statusLabel } from "./advisory";
import { FlawPicker } from "./FlawPicker";

// Every advisory this deployment has minted, newest first.
//
// The rare, deliberate document: single or low double digits a year. So the
// list is for finding one rather than for working through them — no filters,
// no selection, no bulk anything.
//
// An advisory covering a product somebody holds nothing on is not listed and
// the total says the same, which is the server's narrowing. A document is read
// whole or not at all.

export function Advisories() {
  const navigate = useNavigate();
  const [offset, setOffset] = useState(0);
  const rows = useAdvisories(offset);
  const [starting, setStarting] = useState(false);
  const who = useWho();
  // Whoever may record a flaw in a product may write an advisory about one,
  // which is the server's own gate. Drawn to somebody holding no triage
  // anywhere, the control is one that always fails.
  const mayStart = !!who.data?.reach.some((each) => each.may_triage);

  if (rows.isPending) return <Loading />;
  if (rows.isError) return <Failed error={rows.error} what="The advisories could not be read." />;

  const items = rows.data?.items ?? [];
  const total = rows.data?.total;

  return (
    <>
      <div className="screen-head">
        <h2>
          Advisories <span className="n">{(total ?? items.length).toLocaleString()}</span>
        </h2>
        <p>What this deployment has said about its own flaws, newest first.</p>
        {mayStart && (
          <AddButton label="Start an advisory" onClick={() => setStarting((was) => !was)} />
        )}
      </div>

      {starting && (
        <Start onStarted={(made) => navigate(`/advisories/${encodeURIComponent(made)}`)} />
      )}

      {items.length === 0 ? (
        <Empty
          title="No advisories."
          detail="An advisory is about flaws recorded here. Start one from a flaw, here or on the flaw's own page."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Advisory</th>
                <th>Status</th>
                <th className="num">Flaws</th>
                <th className="num">Products</th>
                <th className="num">Out</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.advisory} className="row">
                  <td>
                    <Link className="id" to={`/advisories/${encodeURIComponent(row.advisory)}`}>
                      {row.advisory}
                    </Link>
                    {row.title && <div className="hint">{row.title}</div>}
                  </td>
                  <td>
                    <span
                      className={`state ${standing(row.status)?.tone ?? ""}`}
                      title={standing(row.status)?.means}
                    >
                      {statusLabel(row.status)}
                    </span>
                  </td>
                  <td className="num">{row.issues}</td>
                  <td className="num">{row.products}</td>
                  <td className="num">{row.issuances}</td>
                  <td className="hint">{on(row.minted_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}
      <Paged shown={items.length} total={total} offset={offset} limit={PAGE} onGo={setOffset} />
    </>
  );
}

// Starting an advisory names its first flaw in the same act. An advisory
// covering nothing generates no document, so one started empty is a name with
// nothing behind it and an extra step before anything can be read.
//
// Two requests, because they are two acts on the server: a name is minted,
// then the flaw is named on it. A name already minted is kept for the next
// attempt when the naming is refused, so a mistyped identifier does not spend
// another number from the year's sequence.
function Start({ onStarted }: { onStarted: (advisory: string) => void }) {
  const [product, setProduct] = useState("");
  const [flaw, setFlaw] = useState("");
  const [minted, setMinted] = useState("");
  const after = useAfterAdvisory();
  const start = useMutation({
    mutationFn: async () => {
      let name = minted;
      if (name === "") {
        name = unwrap(await api.POST("/v1/advisories", { body: {} })).advisory;
        setMinted(name);
      }
      unwrap(
        await api.POST("/v1/advisories/{advisory}/issues", {
          params: { path: { advisory: name } },
          body: { product, vulnerability: flaw.trim() },
        }),
      );
      return name;
    },
    onSettled: after,
    onSuccess: onStarted,
  });

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3>Start an advisory</h3>
      <FlawPicker
        product={product}
        onProduct={(next) => {
          setProduct(next);
          setFlaw("");
          start.reset();
        }}
        flaw={flaw}
        onFlaw={setFlaw}
        action={
          <button
            type="button"
            className="btn"
            disabled={!product || !flaw.trim() || start.isPending}
            onClick={() => start.mutate()}
          >
            {start.isPending ? "Starting…" : "Start"}
          </button>
        }
      />
      {start.isError && (
        <Failed
          error={start.error}
          what={
            minted
              ? `${minted} was started and that flaw was not named on it.`
              : "No advisory could be started. Nothing was minted."
          }
        />
      )}
    </div>
  );
}
