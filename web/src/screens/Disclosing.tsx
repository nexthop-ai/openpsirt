import { useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Editor } from "../ui/Editor";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Severity } from "../ui/Severity";
import { Wide } from "../ui/Wide";

// What is approaching disclosure, and where an embargo is moved (a finding
// saying whether it is disclosed, an extension needing agreement).
//
// **Before the date, not on it.** The date arriving is the last moment to act
// rather than the first useful warning, so this lists what is running out as
// well as what has run out — and what has run out sits at the top.
//
// **The list is itself a disclosure.** Every row on it is undisclosed by
// definition, so a product somebody may not read undisclosed work in
// contributes nothing to it, not even a count. That narrowing is the server's.
export function Disclosing() {
  const queries = useQueryClient();
  const [days, setDays] = useState(30);
  const [asking, setAsking] = useState<string | null>(null);
  const [until, setUntil] = useState("");
  const [because, setBecause] = useState("");
  const [said, setSaid] = useState<string | null>(null);

  const rows = useQuery({
    queryKey: ["disclosing", days],
    queryFn: async () =>
      unwrap(await api.GET("/v1/disclosing", { params: { query: { within: days } } })),
  });

  const extend = useMutation({
    mutationFn: async (at: { product: string; vulnerability: string }) =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/disclosure", {
          params: { path: at },
          body: { until, reason: because },
        }),
      ),
    onSuccess: (asked) => {
      setSaid(
        asked.in_force
          ? `The date moved to ${until}.`
          : `Recorded. Nothing moves until a second person agrees, because of how far` +
              ` this embargo has already been moved.`,
      );
      setAsking(null);
      setUntil("");
      setBecause("");
      void queries.invalidateQueries({ queryKey: ["disclosing"] });
    },
  });

  if (rows.isPending) return <Loading />;
  if (rows.isError) {
    return <Failed error={rows.error} what="What is approaching disclosure could not be read." />;
  }
  const items = rows.data?.items ?? [];
  const past = items.filter((row) => row.passed).length;

  return (
    <>
      <div className="screen-head">
        <h2>
          Disclosing <span className="n">{items.length}</span>
        </h2>
        <p>Embargoes running out, soonest first. Reaching a date discloses nothing on its own.</p>
        <label className="field" style={{ marginLeft: "auto" }}>
          <span>Within</span>
          <select value={String(days)} onChange={(event) => setDays(Number(event.target.value))}>
            <option value="7">Within 7 days</option>
            <option value="30">Within 30 days</option>
            <option value="90">Within 90 days</option>
          </select>
        </label>
      </div>

      {said && (
        <div className="alert info" style={{ marginBottom: 12 }}>
          <strong>Asked</strong>
          <span>{said}</span>
        </div>
      )}
      {past > 0 && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>{past} past its date</strong>
          <span>The date has passed with no decision. Nothing has been published.</span>
        </div>
      )}

      {items.length === 0 ? (
        <Empty
          title="Nothing is approaching a disclosure date."
          detail="Recorded flaws under embargo appear here before their date, not on it."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Issue</th>
                <th>Where</th>
                <th>Discloses</th>
                <th className="num">Locations</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((row) => {
                const key = `${row.product} ${row.vulnerability}`;
                return (
                  <tr key={key} className="row">
                    <td>
                      <Severity word={row.severity} />
                    </td>
                    <td>
                      <Link
                        className="id"
                        to={`/products/${encodeURIComponent(row.product ?? "")}/streams/${encodeURIComponent(
                          row.stream ?? "",
                        )}/variants/${encodeURIComponent(row.variant ?? "")}/findings/${encodeURIComponent(
                          row.vulnerability ?? "",
                        )}/components/${encodeURIComponent(row.component ?? "")}`}
                      >
                        {row.vulnerability}
                      </Link>
                      {row.summary && <div className="hint">{row.summary}</div>}
                    </td>
                    <td className="hint">
                      {row.product} · {row.component}
                    </td>
                    <td>
                      <span className={row.passed ? "due over" : "due soon"}>
                        {on(row.disclose_at)}
                        {row.passed && " · past"}
                      </span>
                    </td>
                    <td className="num">{row.places}</td>
                    <td>
                      <button
                        type="button"
                        className="linkish"
                        onClick={() => {
                          setSaid(null);
                          setAsking(asking === key ? null : key);
                          setUntil("");
                          setBecause("");
                        }}
                      >
                        Move the date
                      </button>
                      {asking === key && (
                        <div style={{ marginTop: 8 }}>
                          <p className="hint">
                            Dates only move later. Past a threshold this needs a second person,
                            measured against everything this embargo has already been moved by.
                          </p>
                          <label className="field">
                            <span>Until</span>
                            <input
                              type="date"
                              value={until}
                              onChange={(event) => setUntil(event.target.value)}
                            />
                          </label>
                          <Editor
                            value={because}
                            onChange={setBecause}
                            rows={3}
                            label="Why it is being extended"
                            placeholder="Why the date is moving, and what has to happen before the new one."
                          />
                          <div className="actions" style={{ marginTop: 8 }}>
                            <button
                              type="button"
                              className="btn"
                              disabled={!until || !because.trim() || extend.isPending}
                              onClick={() =>
                                extend.mutate({
                                  product: row.product ?? "",
                                  vulnerability: row.vulnerability ?? "",
                                })
                              }
                            >
                              {extend.isPending ? "Asking…" : "Ask"}
                            </button>
                          </div>
                          {extend.isError && (
                            <Failed error={extend.error} what="That date was not moved." />
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Wide>
      )}
    </>
  );
}
