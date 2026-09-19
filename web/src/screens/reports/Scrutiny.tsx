import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Outcome } from "../../ui/Outcome";
import { on } from "../../ui/when";
import { Sheet } from "./Sheet";
import {
  PeriodPicker,
  WindowPicker,
  asked as askedFor,
  coveringPeriod,
  daysAsked,
  periodAsked,
  stated,
  windowStart,
} from "./Window";
import { Wide } from "../../ui/Wide";

// The window back. Ninety days is a quarter, which is the period an
// audit asks about; the others are here because a control question is
// sometimes about this month and sometimes about the whole record.
//
// Everything is offered because a condition points here. The notification
// saying risk is standing with nobody's agreement counts across the whole
// record, and with nothing longer than a year offered, an administrator sent
// here by it could be told a control failed and shown a page that cannot
// contain the failure at any setting.
const WINDOWS = [30, 90, 365, 3650] as const;

// The three outcomes that hide risk and need a second person. Named here
// because a deferral standing alone reads very differently from a dismissal
// standing alone, and the table has to say which it is looking at.
const DISMISSALS = new Set(["not-applicable", "wont-fix", "already-fixed"]);

// The rows each section carries. Sent rather than left to the server's
// default, because the number has to be the one the notice below quotes: a
// sheet saying "a section reached the limit" without saying what the limit was
// is a sheet nobody can check, and this is a printed record.
const SECTION = 100;

// The work a second pair of eyes actually did.
//
// Not a list of people who broke the rule. The rule cannot be broken:
// approving refuses the proposer and refuses the author of the revision being
// agreed to, and the write is conditional on that revision still being
// current. So the question worth asking is the other one — where did the rule
// not apply, and where did it apply in form only.
export function Scrutiny() {
  const at = useScope();
  const [params] = useSearchParams();
  const days = daysAsked(params, 90);
  const period = periodAsked(params);
  const when = askedFor(period, days);
  const product = at.product ?? "";

  const got = useQuery({
    queryKey: ["scrutiny", product, when],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/approvals/scrutiny", {
          params: { query: { ...when, limit: SECTION, ...(product ? { product } : {}) } },
        }),
      ),
  });

  // The record, narrowed to the set the figure was computed over. A link
  // carrying only the outcome opened the whole record, which is a different
  // population from the sheet's window and product — so the number and the
  // list it opens disagreed.
  const overTheSame = (outcome: string) => {
    const asked = new URLSearchParams({ outcome, alone: "true" });
    // The same stretch the figure was computed over, whichever way it was
    // asked for: a link carrying the rolling window while the sheet is
    // reading a period opens a list the number was never about.
    const began = stated(period) ? period.from : windowStart(days);
    if (began) asked.set("from", began);
    if (period.to) asked.set("to", period.to);
    if (product) asked.set("product", product);
    return `/audit?${asked.toString()}`;
  };

  const alone = got.data?.alone ?? [];
  const dismissed = alone.filter((row) => DISMISSALS.has(row.outcome));
  const exempt = alone.filter((row) => !DISMISSALS.has(row.outcome));

  return (
    <Sheet
      settled={got.isSuccess}
      name="Rubber-stamp"
      answers="how much a second pair of eyes actually did."
      asked={coveringPeriod(period, days)}
    >
      <WindowPicker offered={WINDOWS} days={days} />
      <PeriodPicker period={period} />

      {got.isPending ? (
        <Loading />
      ) : got.isError ? (
        <Failed error={got.error} what="How approvals are going could not be read." />
      ) : (
        <>
          <section className="panel">
            <h3>What the control cannot do</h3>
            <p className="reading">
              Neither control can be waived. Read this for where they did not apply, or applied in
              form only.
            </p>
          </section>

          {/* Said, not implied. Every row below is an exception to the
              two-person rule, and a ninety-day window can hold more of them
              than one section carries — so a sheet that read as complete while
              it was clipped would mislead exactly the reader it is for. */}
          {got.data?.capped && (
            <p className="alert" style={{ marginTop: 14 }}>
              <strong>Not all of it.</strong>
              <span>
                A section reached {SECTION.toLocaleString()} rows. What follows is the worst of it,
                not the whole of it. Narrow the window or the product to see a section whole.
              </span>
            </p>
          )}

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Risk standing on one person</h3>
            {/* The two halves read completely differently, so they are drawn
                apart rather than sorted together. One is the exception the
                rule carries; the other is the rule not having held. */}
            {dismissed.length > 0 ? (
              <>
                <p className="hint" style={{ marginTop: 0 }}>
                  Dismissals always need a second person. Every row here is a control that did not
                  hold.
                </p>
                <Wide>
                  <table>
                    <thead>
                      <tr>
                        <th>Claimed</th>
                        <th className="num">Acts</th>
                        <th className="num">Decisions</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {dismissed.map((row) => (
                        <tr key={row.outcome} className="row">
                          <td>
                            <Outcome outcome={row.outcome} />
                          </td>
                          <td className="num">{(row.claims ?? 0).toLocaleString()}</td>
                          <td className="num">{(row.rows ?? 0).toLocaleString()}</td>
                          <td>
                            <Link to={overTheSame(row.outcome ?? "")} className="linkish">
                              Read them →
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Wide>
              </>
            ) : (
              <Empty
                title="No dismissal stands on one person's say-so."
                detail="Every dismissal requires a second person. This checks the record."
              />
            )}

            <h4 style={{ marginTop: 16 }}>Where the rule did not apply</h4>
            <p className="hint">
              Short deferrals stand on their own, measured against the total already deferred.
            </p>
            {exempt.length === 0 ? (
              <p className="hint">Nothing stands on one person in this window.</p>
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Claimed</th>
                      <th className="num">Acts</th>
                      <th className="num">Decisions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {exempt.map((row) => (
                      <tr key={row.outcome}>
                        <td>
                          <Outcome outcome={row.outcome} />
                        </td>
                        <td className="num">{(row.claims ?? 0).toLocaleString()}</td>
                        <td className="num">{(row.rows ?? 0).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Who agrees with whom</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              Concentration is the signal, and a count alone does not carry it: fifty out of
              fifty-two and fifty out of nine hundred are the same number and not the same
              situation. A share is of every decision a standing agreement covers in this window —{" "}
              {(got.data?.agreed ?? 0).toLocaleString()} of them.
            </p>
            {(got.data?.pairs ?? []).length === 0 ? (
              <p className="hint">Nobody has agreed to anything in this window.</p>
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Proposed by</th>
                      <th>Agreed by</th>
                      <th className="num">Claims</th>
                      <th className="num">Decisions</th>
                      <th className="num">Share</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(got.data?.pairs ?? []).map((row) => (
                      <tr key={`${row.proposer} ${row.approver}`} className="row">
                        <td className="id">{row.proposer}</td>
                        <td className="id">{row.approver}</td>
                        <td className="num">{(row.claims ?? 0).toLocaleString()}</td>
                        <td className="num">{(row.rows ?? 0).toLocaleString()}</td>
                        <td className="num">{row.share}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Agreements given in bulk</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              A batch is agreed as one act, so a batch of two hundred is not a batch of two.
            </p>
            {(got.data?.bulk ?? []).length === 0 ? (
              <p className="hint">Nothing was agreed to in bulk in this window.</p>
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Batch</th>
                      <th>Agreed by</th>
                      <th>When</th>
                      <th className="num">Claims</th>
                      <th className="num">Decisions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(got.data?.bulk ?? []).map((row) => (
                      <tr key={`${row.batch} ${row.approved_by}`} className="row">
                        <td className="id">{row.batch}</td>
                        <td className="id">{row.approved_by}</td>
                        <td>{on(row.approved_at)}</td>
                        <td className="num">{(row.claims ?? 0).toLocaleString()}</td>
                        <td className="num">{(row.rows ?? 0).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Agreed to before, covering more now</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              Compares what was agreed against what the claim reaches now.
            </p>
            {(got.data?.grew ?? []).length === 0 ? (
              <p className="hint">Nothing covers more than it did when it was agreed to.</p>
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Claim</th>
                      <th>Claimed</th>
                      <th>Agreed by</th>
                      <th className="num">Agreed to</th>
                      <th className="num">Covers now</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(got.data?.grew ?? []).map((row) => (
                      <tr key={row.claim_id} className="row">
                        <td>
                          <Link to={`/claims/${row.claim_id}`} className="id">
                            {row.claim_id}
                          </Link>
                        </td>
                        <td>
                          <Outcome outcome={row.outcome} />
                        </td>
                        <td className="id">{row.approved_by}</td>
                        <td className="num">{(row.covered ?? 0).toLocaleString()}</td>
                        <td className="num state open">{(row.covers_now ?? 0).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Standing from somebody who could not give it now</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              These still stand: losing a role does not undo an approval. Still the first list asked
              for after a reorganization.
            </p>
            {(got.data?.lapsed ?? []).length === 0 ? (
              <p className="hint">Everyone whose agreement stands could still give it.</p>
            ) : (
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Claim</th>
                      <th>Product</th>
                      <th>Claimed</th>
                      <th>Agreed by</th>
                      <th>When</th>
                      <th className="num">Decisions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(got.data?.lapsed ?? []).map((row) => (
                      <tr key={`${row.claim_id} ${row.approved_by}`} className="row">
                        <td>
                          <Link to={`/claims/${row.claim_id}`} className="id">
                            {row.claim_id}
                          </Link>
                        </td>
                        <td>{row.product}</td>
                        <td>
                          <Outcome outcome={row.outcome} />
                        </td>
                        <td className="id">{row.approved_by}</td>
                        <td>{on(row.approved_at)}</td>
                        <td className="num">{(row.rows ?? 0).toLocaleString()}</td>
                      </tr>
                    ))}
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
