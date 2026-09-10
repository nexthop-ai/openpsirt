import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { on } from "../../ui/when";
import { Sheet } from "./Sheet";

// How far back to look. A year by default, because publishing is rare enough
// that a month of it is usually nothing and reads as a tool that is not working.
const WINDOWS = [90, 365, 3650] as const;

// What has been published, and what was published twice.
//
// **Answered per flaw until now.** That is the right shape for somebody about
// to publish a revision — has one gone out, and is what is out still what we
// would generate — and the wrong shape for the question a period asks.
//
// **Advisories are about flaws in our own product**, recorded here by hand.
// Known issues in third-party components are tracked and fixed rather than
// published about; the document for those is a VEX statement per build, which
// the catalog offers as a file.
export function Published() {
  const at = useScope();
  const [params, setParams] = useSearchParams();
  const days = Number(params.get("days") ?? 365);
  const product = at.product ?? "";

  const gone = useQuery({
    queryKey: ["published", product, days],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/advisories", {
          params: { query: { days, ...(product ? { product } : {}) } },
        }),
      ),
  });

  const rows = gone.data?.items ?? [];
  const revisions = rows.filter((row) => (row.ordinal ?? 1) > 1).length;

  return (
    <Sheet
      name="Advisories issued"
      answers="what has been published about our own flaws, and what was published twice."
      asked={windowWords(days)}
    >
      <div className="controls">
        <div className="seg" role="group" aria-label="Window">
          {WINDOWS.map((n) => (
            <button
              key={n}
              type="button"
              aria-pressed={days === n}
              onClick={() => {
                const next = new URLSearchParams(params);
                next.set("days", String(n));
                setParams(next);
              }}
            >
              {n === 3650 ? "everything" : n === 365 ? "a year" : "90 days"}
            </button>
          ))}
        </div>
      </div>

      {gone.isPending ? (
        <Loading />
      ) : gone.isError ? (
        <Failed error={gone.error} what="What has been published could not be read." />
      ) : rows.length === 0 ? (
        <section className="panel">
          <Empty
            title="Nothing has been published in this window."
            detail="An advisory is about a flaw in our own product, recorded here by hand. Known issues in third-party components are tracked and fixed rather than published about."
          />
        </section>
      ) : (
        <section className="panel">
          <h3>
            {rows.length.toLocaleString()} {rows.length === 1 ? "advisory" : "advisories"}
            {revisions > 0 && `, ${revisions.toLocaleString()} of them a revision`}
          </h3>
          <p className="hint" style={{ marginTop: 0 }}>
            Newest first. A revision is an advisory that had already gone out and was published
            again — the entry a period is usually read for. The digest is what the document hashed
            to when it went out: the published document belongs to whoever published it, and this is
            what makes &ldquo;is what is out still what we would generate&rdquo; a question with an
            answer.
          </p>
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>Flaw</th>
                  <th>Product</th>
                  <th>Revision</th>
                  <th>Published</th>
                  <th>By</th>
                  <th>Said</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.product} ${row.issue} ${row.ordinal}`} className="row">
                    <td>
                      <Link to={`/issues/${encodeURIComponent(row.issue ?? "")}`} className="id">
                        {row.issue}
                      </Link>
                    </td>
                    <td>{row.product}</td>
                    <td>
                      {(row.ordinal ?? 1) > 1 ? (
                        <span className="state open">revision {(row.ordinal ?? 1) - 1}</span>
                      ) : (
                        <span className="hint">first</span>
                      )}
                    </td>
                    <td>{on(row.issued_at)}</td>
                    <td className="id">{row.issued_by}</td>
                    <td className="hint" style={{ maxWidth: "40ch" }}>
                      {row.summary || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </Sheet>
  );
}

// What the window is, in the words the buttons use.
function windowWords(days: number): string {
  if (days >= 3650) return "everything";
  if (days === 365) return "the last year";
  return `the last ${days} days`;
}
