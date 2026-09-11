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
import { WindowPicker, coveringWords } from "./Window";

// How long back to look. Ninety days is a quarter, which is the period an
// audit asks about; the other two are here because a control question is
// sometimes about this month and sometimes about the whole record.
const WINDOWS = [30, 90, 365] as const;

// The three outcomes that hide risk and need a second person. Named here
// because a deferral standing alone reads very differently from a dismissal
// standing alone, and the table has to say which it is looking at.
const DISMISSALS = new Set(["not-applicable", "wont-fix", "already-fixed"]);

// How much a second pair of eyes actually did.
//
// **Not a list of people who broke the rule.** The rule cannot be broken:
// approving refuses the proposer and refuses the author of the revision being
// agreed to, and the write is conditional on that revision still being
// current. So the question worth asking is the other one — where did the rule
// not apply, and where did it apply in form only.
export function Scrutiny() {
  const at = useScope();
  const [params] = useSearchParams();
  const days = Number(params.get("days") ?? 90);
  const product = at.product ?? "";

  const got = useQuery({
    queryKey: ["scrutiny", product, days],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/approvals/scrutiny", {
          params: { query: { days, ...(product ? { product } : {}) } },
        }),
      ),
  });

  const alone = got.data?.alone ?? [];
  const dismissed = alone.filter((row) => DISMISSALS.has(row.outcome));
  const exempt = alone.filter((row) => !DISMISSALS.has(row.outcome));

  return (
    <Sheet
      name="Rubber-stamp"
      answers="how much a second pair of eyes actually did."
      asked={coveringWords(days)}
    >
      <WindowPicker offered={WINDOWS} days={days} />

      {got.isPending ? (
        <Loading />
      ) : got.isError ? (
        <Failed error={got.error} what="How approvals are going could not be read." />
      ) : (
        <>
          <section className="panel">
            <h3>What the control cannot do</h3>
            <p className="reading">
              A proposer may never approve their own claim, and never the words of a revision they
              wrote themselves; the agreement points at one revision, so editing the reasoning takes
              it back. None of that can be waived, so nothing below is a list of people who broke a
              rule. What is worth reading is where the rule did not apply, and where it applied in
              form only.
            </p>
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Risk standing on one person</h3>
            {/* The two halves read completely differently, so they are drawn
                apart rather than sorted together. One is the exception the
                rule carries; the other is the rule not having held. */}
            {dismissed.length > 0 ? (
              <>
                <p className="hint" style={{ marginTop: 0 }}>
                  A dismissal hides risk and always needs a second person. Every row here is a
                  control that did not hold — read them.
                </p>
                <div className="tablewrap">
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
                            <Link
                              to={`/audit?outcome=${row.outcome}&alone=true`}
                              className="linkish"
                            >
                              Read them →
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <Empty
                title="No dismissal stands on one person's say-so."
                detail="Which is the answer this half exists to get. Every dismissal requires a second person, and this asks the record whether one is there rather than whether the rule exists."
              />
            )}

            <h4 style={{ marginTop: 16 }}>Where the rule did not apply</h4>
            <p className="hint">
              A short deferral stands on its own, and so does an upgrade promised inside the
              deadline the work already had. Both are deliberate: gating every routine act would put
              the most ordinary judgment through a queue, which is how a queue stops being read. One
              at a time this is triage. The pattern across a program is what nothing else shows, and
              &ldquo;short&rdquo; is measured against everything the same finding has already been
              put off for — otherwise the exception swallows the rule one twenty-nine-day deferral
              at a time.
            </p>
            {exempt.length === 0 ? (
              <p className="hint">Nothing stands on one person in this window.</p>
            ) : (
              <div className="tablewrap">
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
              </div>
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
              <div className="tablewrap">
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
              </div>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Agreements given in bulk</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              An approver works at the unit the proposer acted at, so agreeing to a batch as one act
              is the control working rather than a shortcut around it. A batch of two hundred is
              still a different thing from a batch of two.
            </p>
            {(got.data?.bulk ?? []).length === 0 ? (
              <p className="hint">Nothing was agreed to in bulk in this window.</p>
            ) : (
              <div className="tablewrap">
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
              </div>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Agreed to before, covering more now</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              A judgment reaches by matching, so a build appearing afterwards is covered with nobody
              acting — and nobody having agreed to the larger number. What somebody consented to is
              recorded when they consented; this is that against what the same claim reaches today.
            </p>
            {(got.data?.grew ?? []).length === 0 ? (
              <p className="hint">Nothing covers more than it did when it was agreed to.</p>
            ) : (
              <div className="tablewrap">
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
              </div>
            )}
          </section>

          <section className="panel" style={{ marginTop: 14 }}>
            <h3>Standing from somebody who could not give it now</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              An approval is a fact about a moment, so it is right that these still stand — losing a
              role does not un-say what somebody said. It is still the first list asked for after a
              reorganization.
            </p>
            {(got.data?.lapsed ?? []).length === 0 ? (
              <p className="hint">Everyone whose agreement stands could still give it.</p>
            ) : (
              <div className="tablewrap">
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
              </div>
            )}
          </section>
        </>
      )}
    </Sheet>
  );
}
