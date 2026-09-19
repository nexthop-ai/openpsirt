import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { findingsPath, scopeQuery, useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Severity } from "../../ui/Severity";
import { Sheet } from "./Sheet";
import { PeriodPicker, asked, coveringPeriod, periodAsked, stated } from "./Window";
import { Wide } from "../../ui/Wide";

// Whether work met the dates policy set for it.
//
// The question a manager asks first, and it was answered by one figure with
// nothing behind it. A single percentage cannot be acted on: it does not say
// which severity is slipping, how much of the shortfall was deliberate, or what
// is late right now as against what was late once.
//
// A deferral is its own number and never a failure. A rate that counted an
// approved deferral as one would punish the deliberate act the deferral
// mechanism exists to make possible, and within a quarter people stop deferring
// and start letting work run late quietly instead — which is the same risk with
// nothing recorded against it.
export function Compliance() {
  const at = useScope();
  const scope = scopeQuery(at);
  const product = at.product ?? "";
  const [params] = useSearchParams();
  // No window by default, which is the lifetime figure this has always
  // answered. A period is what a quarterly review or a financial year asks
  // for, and it bounds what closed in it — what is open is always now.
  const period = periodAsked(params);
  const when = asked(period, 0);

  const rates = useQuery({
    enabled: product !== "",
    queryKey: ["compliance", scope, when],
    queryFn: async () =>
      unwrap(await api.GET("/v1/compliance", { params: { query: { ...when, ...scope } } })),
  });

  const rows = rates.data?.items ?? [];
  const whole = rows.reduce(
    (sum, row) => ({
      closed: sum.closed + (row.closed ?? 0),
      met: sum.met + (row.met ?? 0),
      late: sum.late + (row.late ?? 0),
      deferred: sum.deferred + (row.deferred ?? 0),
      overdue: sum.overdue + (row.overdue ?? 0),
    }),
    { closed: 0, met: 0, late: 0, deferred: 0, overdue: 0 },
  );

  return (
    <Sheet
      settled={rates.isSuccess}
      name="Deadline compliance"
      answers="whether work met the dates policy set for it."
      asked={stated(period) ? coveringPeriod(period, 0) : undefined}
    >
      {product !== "" && <PeriodPicker period={period} />}
      {product === "" ? (
        <section className="panel">
          <Empty
            title="Pick a product."
            detail="A rate has to be about one product, because a place identity carries none."
          />
        </section>
      ) : rates.isPending ? (
        <Loading />
      ) : rates.isError ? (
        <Failed error={rates.error} what="The compliance rate could not be read." />
      ) : (
        <>
          <section className="panel">
            <h3>What closed, and whether it closed in time</h3>
            <div className="kpis" style={{ marginTop: 8 }}>
              <div className="kpi">
                <span className="l">Met its deadline</span>
                <span className="n">{rate(whole.met, whole.closed)}</span>
                <span className="d">
                  {whole.met.toLocaleString()} of {whole.closed.toLocaleString()} closed. Closed
                  exactly at the deadline met it — something still open at that instant is not yet
                  overdue
                </span>
              </div>
              <div className="kpi">
                <span className="l">Deferred by decision</span>
                <span className="n">{whole.deferred.toLocaleString()}</span>
                <span className="d">
                  still open, with the date deliberately moved. Neither met nor late
                </span>
              </div>
              <Link
                className="kpi"
                to={`${findingsPath(at)}?overdue=true`}
                aria-label="Open what is overdue"
              >
                <span className="l">Plainly late</span>
                <span className="n">{whole.overdue.toLocaleString()}</span>
                <span className="d">still open, past the date, with nothing standing over it</span>
              </Link>
            </div>
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>By severity</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              Issues at components. A group is closed only when no place of it is still open.
            </p>
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th className="num">Closed</th>
                    <th className="num">Met</th>
                    <th className="num">Late</th>
                    <th className="num">Rate</th>
                    <th className="num">Deferred</th>
                    <th className="num">Overdue</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.severity} className="row">
                      <td>
                        <Severity word={row.severity} />
                      </td>
                      <td className="num">{(row.closed ?? 0).toLocaleString()}</td>
                      <td className="num">{(row.met ?? 0).toLocaleString()}</td>
                      <td className="num">{(row.late ?? 0).toLocaleString()}</td>
                      <td className="num">{rate(row.met ?? 0, row.closed ?? 0)}</td>
                      <td className="num">{(row.deferred ?? 0).toLocaleString()}</td>
                      {/* A number rather than a link, deliberately. The
                          findings list reads a severity as "this badly or
                          worse", so a link from the high row would open high
                          and critical together — more than the row counts. A
                          figure whose list holds something else is the defect
                          this page would otherwise ship; the whole-of-it link
                          above needs no severity and is exact. */}
                      <td className="num">
                        {(row.overdue ?? 0) > 0 ? (
                          <span className="state open">{(row.overdue ?? 0).toLocaleString()}</span>
                        ) : (
                          <span className="hint">none</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Wide>
          </section>

          {/* What a rate about deadlines cannot be about, said here rather
              than left to be discovered. Each of these carries no deadline by
              design, so none of them is in any figure above — and one of them
              has a report of its own. */}
          <section className="panel" style={{ marginTop: 14 }}>
            <h3>What is not in these figures</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              These carry no deadline, so nothing about them can be late.
            </p>
            <ul className="files">
              <li>
                <b>Below the line this product triages at.</b> Recorded and counted, but not worked
                to a date.
              </li>
              <li>
                <b>Findings in a tag.</b> Tags are built once, so no work lands in them.
              </li>
              <li>
                <b>Findings upstream has released no fix for, or has declined to fix.</b> There is
                no version that would close them, so the only thing that could stop the clock is
                somebody recording a judgment — which is the act a deadline exists to ask for.
              </li>
              <li>
                <b>Findings in a release out of support.</b> That pile has a report of its own —{" "}
                <Link to="/reports/releases-out-of-support">Releases out of support</Link> — absent
                from every figure built on a deadline.
              </li>
            </ul>
          </section>
        </>
      )}
    </Sheet>
  );
}

// A rate, or a dash where nothing has closed. Zero of zero is not nought per
// cent: it is a question nobody has an answer to yet, and printing "0%" beside
// a band nothing closed in reads as a failure.
function rate(met: number, closed: number): string {
  if (closed === 0) return "—";
  return `${Math.round((met / closed) * 100)}%`;
}
