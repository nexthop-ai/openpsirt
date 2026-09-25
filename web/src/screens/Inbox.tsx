// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import { PAGE, useReports, useRulings } from "../api/intake";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { rulable, standing } from "./inbox";
import { RuleForm, RulingCard, useBackOff } from "./InboxRuling";
import { Count } from "../ui/Count";

// One product's reports: what arrived, what it was judged to be, and the
// rulings waiting on a second person.
//
// A ruling covers a selection, because slop arrives in numbers and twenty of
// it rejected in one sentence takes one approval.
export function Inbox() {
  const { product = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("waiting") ? "waiting" : "reports";
  const go = (next: "reports" | "waiting") =>
    setParams(next === "waiting" ? { waiting: "1" } : {}, { replace: true });
  const waiting = useRulings(product, true, 0);
  // Reading reports and working them are different rights, so a reader of
  // undisclosed work sees every report and none of the controls that write.
  const works = !!mayOf(useWho().data, product)?.may_hide;

  return (
    <div>
      <div className="screen-head">
        <h2>Inbox</h2>
        <p>
          Vulnerability reports sent to{" "}
          <Link to={`/products/${encodeURIComponent(product)}`}>{product}</Link>
        </p>
        {/* The one form every flaw is reported through, found here or sent
            in, with this product already picked. */}
        {works && (
          <Link className="btn" to={`/record?product=${encodeURIComponent(product)}`}>
            Report a flaw
          </Link>
        )}
      </div>

      <div className="tabs2">
        <button
          type="button"
          className="tab2"
          aria-selected={tab === "reports"}
          onClick={() => go("reports")}
        >
          Vulnerability reports
        </button>
        <button
          type="button"
          className={`tab2${(waiting.data?.total ?? 0) > 0 ? " urgent" : ""}`}
          aria-selected={tab === "waiting"}
          onClick={() => go("waiting")}
        >
          Waiting for approval{" "}
          <span className="n">
            <Count of={waiting}>{() => (waiting.data?.total ?? 0).toLocaleString()}</Count>
          </span>
        </button>
      </div>

      {tab === "reports" ? (
        <Reports product={product} works={works} />
      ) : (
        <Waiting product={product} />
      )}
    </div>
  );
}

function Reports({ product, works }: { product: string; works: boolean }) {
  const [offset, setOffset] = useState(0);
  const [chosen, setChosen] = useState<string[]>([]);
  const listed = useReports(product, offset);

  if (listed.isPending) return <Loading />;
  if (listed.isError)
    return <Failed error={listed.error} what="The vulnerability reports could not be read." />;
  const rows = listed.data?.items ?? [];
  const at = `/products/${encodeURIComponent(product)}/inbox`;
  const open = rows.filter(rulable).map((row) => row.reference);
  const toggle = (reference: string) =>
    setChosen((was) =>
      was.includes(reference) ? was.filter((each) => each !== reference) : [...was, reference],
    );

  if (rows.length === 0) {
    return (
      <Empty
        title="No vulnerability reports."
        detail="Every flaw reported in this product appears here, sent in or found here."
      />
    );
  }
  return (
    <>
      {chosen.length > 0 && (
        <div className="card" style={{ marginBottom: 12 }}>
          <h3>
            {chosen.length} selected{" "}
            <button type="button" className="btn quiet" onClick={() => setChosen([])}>
              Clear
            </button>
          </h3>
          <RuleForm product={product} references={chosen} onDone={() => setChosen([])} />
        </div>
      )}
      <Wide>
        <table>
          <thead>
            <tr>
              <th hidden={!works}>
                <input
                  type="checkbox"
                  aria-label="Select every open vulnerability report on this page"
                  checked={open.length > 0 && open.every((each) => chosen.includes(each))}
                  disabled={open.length === 0}
                  onChange={(event) => setChosen(event.target.checked ? open : [])}
                />
              </th>
              <th>Report</th>
              <th>From</th>
              <th>Arrived</th>
              <th>Answered</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const stands = standing(row);
              return (
                <tr key={row.reference} className="row">
                  <td hidden={!works}>
                    {rulable(row) && (
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.reference}`}
                        checked={chosen.includes(row.reference)}
                        onChange={() => toggle(row.reference)}
                      />
                    )}
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <Link className="id" to={`${at}/${encodeURIComponent(row.reference)}`}>
                      {row.reference}
                    </Link>
                  </td>
                  <td>
                    {row.found_here ? (
                      <span className="hint">
                        found here{row.reported_by && ` · ${row.reported_by}`}
                      </span>
                    ) : (
                      row.reported_by || <span className="hint">—</span>
                    )}
                  </td>
                  <td className="hint">{row.received || on(row.recorded_at)}</td>
                  <td className="hint">
                    {row.found_here ? (
                      "—"
                    ) : row.acknowledged ? (
                      on(row.acknowledged)
                    ) : (
                      <span className="alertish">not yet</span>
                    )}
                  </td>
                  <td>
                    <span className={`state ${stands.tone}`}>{stands.said}</span>
                    {row.issue && (
                      <>
                        {" "}
                        <Link className="id" to={`/issues/${encodeURIComponent(row.issue)}`}>
                          {row.issue}
                        </Link>
                      </>
                    )}
                    {row.duplicate_of && (
                      <>
                        {" "}
                        of{" "}
                        <Link className="id" to={`/issues/${encodeURIComponent(row.duplicate_of)}`}>
                          {row.duplicate_of}
                        </Link>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Wide>
      <Paged
        shown={rows.length}
        total={listed.data?.total}
        offset={offset}
        limit={PAGE}
        onGo={(next) => {
          setChosen([]);
          setOffset(next);
        }}
      />
    </>
  );
}

function Waiting({ product }: { product: string }) {
  const [offset, setOffset] = useState(0);
  const listed = useRulings(product, true, offset);
  useBackOff(listed.data?.items?.length, offset, setOffset);
  if (listed.isPending) return <Loading />;
  if (listed.isError) return <Failed error={listed.error} what="The rulings could not be read." />;
  const rows = listed.data?.items ?? [];
  if ((listed.data?.total ?? 0) === 0) {
    return <Empty title="Nothing waiting." />;
  }
  return (
    <>
      {rows.map((ruling) => (
        <RulingCard key={ruling.id} ruling={ruling} />
      ))}
      <Paged
        shown={rows.length}
        total={listed.data?.total}
        offset={offset}
        limit={PAGE}
        onGo={setOffset}
      />
    </>
  );
}
