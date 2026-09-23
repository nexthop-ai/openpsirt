// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { mayOf, useWho } from "../app/session";
import { PAGE, useRecordReport, useReports, useRulings } from "../api/intake";
import { Editor } from "../ui/Editor";
import { notACredential } from "../ui/noautofill";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { rulable, standing } from "./inbox";
import { RuleForm, RulingCard, useBackOff } from "./InboxRuling";

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
  const [recording, setRecording] = useState(false);
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
        {works && (
          <button type="button" className="btn" onClick={() => setRecording((was) => !was)}>
            {recording ? "Cancel" : "Record a vulnerability report"}
          </button>
        )}
      </div>

      {recording && <RecordReport product={product} />}

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
          <span className="n">{(waiting.data?.total ?? 0).toLocaleString()}</span>
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
        detail="A vulnerability report you record appears here."
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
                  <td>{row.reported_by || <span className="hint">—</span>}</td>
                  <td className="hint">{row.received || on(row.recorded_at)}</td>
                  <td className="hint">
                    {row.acknowledged ? (
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

// Writing down a report that arrived. Only what was claimed is required: a
// report arriving anonymously is an ordinary report.
function RecordReport({ product }: { product: string }) {
  const navigate = useNavigate();
  const record = useRecordReport(product);
  const [summary, setSummary] = useState("");
  const [reportedBy, setReportedBy] = useState("");
  const [contact, setContact] = useState("");
  const [credit, setCredit] = useState("");
  const [received, setReceived] = useState("");

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <h3>New vulnerability report</h3>
      <div className="field">
        <Editor
          label="What was claimed"
          value={summary}
          onChange={setSummary}
          rows={6}
          draftKey={`report:${product}`}
        />
      </div>
      <div
        style={{
          display: "grid",
          gap: 10,
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
        }}
      >
        <div className="field">
          <label htmlFor="reported-by">From</label>
          <input
            {...notACredential}
            id="reported-by"
            type="text"
            value={reportedBy}
            onChange={(e) => setReportedBy(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="contact">Contact</label>
          <input
            {...notACredential}
            id="contact"
            type="text"
            value={contact}
            onChange={(e) => setContact(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="credit">Credit as</label>
          <input
            {...notACredential}
            id="credit"
            type="text"
            value={credit}
            onChange={(e) => setCredit(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="received">Arrived</label>
          <input
            {...notACredential}
            id="received"
            type="date"
            value={received}
            onChange={(e) => setReceived(e.target.value)}
          />
        </div>
      </div>
      <button
        type="button"
        className="btn"
        disabled={summary.trim() === "" || record.isPending}
        onClick={() =>
          record.mutate(
            {
              summary: summary.trim(),
              ...(reportedBy.trim() ? { reported_by: reportedBy.trim() } : {}),
              ...(contact.trim() ? { contact: contact.trim() } : {}),
              ...(credit.trim() ? { credit: credit.trim() } : {}),
              ...(received ? { received } : {}),
            },
            {
              onSuccess: (made) =>
                navigate(
                  `/products/${encodeURIComponent(product)}/inbox/${encodeURIComponent(made.reference)}`,
                ),
            },
          )
        }
      >
        Record
      </button>
      {record.error != null && (
        <Failed error={record.error} what="The vulnerability report was not recorded." />
      )}
    </div>
  );
}
