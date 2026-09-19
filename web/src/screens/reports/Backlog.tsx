import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { scopeQuery, useScope } from "../../app/scope";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Mix, Pace, folded } from "../../ui/Charts";
import { Empty } from "../../ui/Empty";
import { Sheet } from "./Sheet";
import { Wide } from "../../ui/Wide";
// The ladder, written down once. The columns are fixed rather than read off
// the data: ones that appear and vanish with the rows are columns nobody can
// build a spreadsheet against.
import { BANDS } from "../../ui/severities";

// The direction of the backlog, and the kind of thing making it move.
//
// The first question a manager asks, and it was a panel on the home screen
// at a fixed twelve weeks — no name, no window, no file, and no way to ask
// it of anything but the selection the shell happened to be on.
//
// The two flows are what a backlog is read for. Ten arriving and ten answered
// is a team keeping pace where both are low, and a team losing ground where
// what arrives is critical and what leaves is not — which a line of totals
// draws as flat.

// The windows worth asking this over. A quarter is the shortest that shows a
// trend rather than a fortnight's noise, and two years is the longest the
// server answers for.
const WEEKS = [4, 13, 26, 52, 104] as const;

// weeksAsked is the window the address asks for, checked rather than trusted:
// it reaches the server, which refuses what it cannot answer, and a value that
// is not a whole number of weeks in range falls back to a quarter.
export function weeksAsked(params: URLSearchParams, fallback = 13): number {
  const asked = params.get("weeks");
  if (asked === null) return fallback;
  const weeks = Number(asked);
  if (!Number.isFinite(weeks) || weeks < 1 || weeks > 104) return fallback;
  return Math.floor(weeks);
}

export function Backlog() {
  const at = useScope();
  const scope = scopeQuery(at);
  const [params, setParams] = useSearchParams();
  const weeks = weeksAsked(params);

  const trend = useQuery({
    queryKey: ["backlog", scope, weeks],
    queryFn: async () =>
      unwrap(await api.GET("/v1/trend", { params: { query: { ...scope, weeks } } })),
  });

  const points = trend.data?.items ?? [];
  // The first step has nothing to differ from, so it reports neither flow.
  // Drawn, it is a zero somebody reads as a quiet week.
  const flows = points.slice(1);
  const asked = new URLSearchParams({ ...scope, weeks: String(weeks) }).toString();
  const file = (format: string) => `/v1/trend.${format}${asked ? `?${asked}` : ""}`;

  return (
    <Sheet
      settled={trend.isSuccess}
      name="Backlog over time"
      answers="whether the backlog is growing, and what kind of thing is making it grow."
      asked={`${weeks} weeks`}
    >
      <div className="controls">
        <div className="seg" role="group" aria-label="Window">
          {WEEKS.map((n) => (
            <button
              key={n}
              type="button"
              aria-pressed={weeks === n}
              onClick={() => {
                const next = new URLSearchParams(params);
                next.set("weeks", String(n));
                setParams(next);
              }}
            >
              {n === 104 ? "two years" : n === 52 ? "a year" : `${n} weeks`}
            </button>
          ))}
        </div>
        <span style={{ marginLeft: "auto" }} className="noprint">
          <a className="btn quiet" href={file("csv")}>
            CSV
          </a>{" "}
          <a className="btn quiet" href={file("json")}>
            JSON
          </a>
        </span>
      </div>

      {trend.isPending ? (
        <Loading />
      ) : trend.isError ? (
        <Failed error={trend.error} what="The backlog could not be read." />
      ) : points.length === 0 ? (
        <Empty
          title="Nothing has been scanned yet."
          detail="A trend is what changed between scans, so it starts with the second one."
        />
      ) : (
        <>
          <section className="panel">
            <h3>Open, new and resolved</h3>
            <Pace points={points} />
            <div className="legend">
              <span>
                <i style={{ background: "var(--accent)" }} /> Open issues
              </span>
              <span>
                <i style={{ background: "var(--sev-high)" }} /> New
              </span>
              <span>
                <i style={{ background: "var(--ok)" }} /> Resolved
              </span>
            </div>
            <p className="hint">Counted as issues, not as places.</p>
          </section>

          <section className="panel">
            <h3>What is open, by severity</h3>
            <Mix points={points} />
            <p className="hint">The share matters as much as the total.</p>
          </section>

          <section className="panel">
            <h3>What arrived, and what was answered</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              Both flows, split the same way.
            </p>
            {flows.length === 0 ? (
              <Empty
                title="One step is not a trend."
                detail="What arrived and what was answered are the difference between two steps, so this needs a second one."
              />
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Week ending</th>
                      <th>New</th>
                      {BANDS.map((band) => (
                        <th key={`in ${band}`}>{band}</th>
                      ))}
                      <th>Resolved</th>
                      {BANDS.map((band) => (
                        <th key={`out ${band}`}>{band}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {flows.map((point) => {
                      const arrived = folded(point.opened_by_severity ?? {});
                      const answered = folded(point.resolved_by_severity ?? {});
                      return (
                        <tr key={point.at}>
                          <td className="id">{point.at}</td>
                          <td>{(point.opened ?? 0).toLocaleString()}</td>
                          {BANDS.map((band) => (
                            <td key={`in ${band}`} className="hint">
                              {(arrived[band] ?? 0).toLocaleString()}
                            </td>
                          ))}
                          <td>{(point.resolved ?? 0).toLocaleString()}</td>
                          {BANDS.map((band) => (
                            <td key={`out ${band}`} className="hint">
                              {(answered[band] ?? 0).toLocaleString()}
                            </td>
                          ))}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </Wide>
            )}
          </section>
        </>
      )}
    </Sheet>
  );
}
