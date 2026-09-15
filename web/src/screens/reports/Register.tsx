import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Outcome } from "../../ui/Outcome";
import { Paged } from "../../ui/Paged";
import { Severity } from "../../ui/Severity";
import { on } from "../../ui/when";
import { Sheet } from "./Sheet";
import { Wide } from "../../ui/Wide";

// How much of the register one page holds. The server's own ceiling is five
// hundred; this is what somebody reads before paging, and the file is what
// they take away.
const PAGE = 200;

// Every known vulnerability in one build, and what became of it.
//
// **The complement of the record, not a variant of it.** The record says what
// was decided; an auditor's first question is what was *known*, decided or not.
// So a row nobody has said anything about is in here, and so is a closed one —
// a register of what is still open answers a different question from the one it
// would appear to answer.
//
// **One row per issue and place**, unfolded. Every other list here groups,
// because a person reading a list wants the judgment rather than the repetition;
// a register is read against what shipped, and what shipped is places.
//
// **It states no triage line because it applies none.** Everything in the build
// is here whatever the deployment considers worth triaging, which is the basis
// on which somebody can rely on it.
export function Register() {
  const at = useScope();
  const [offset, setOffset] = useState(0);
  const whole = Boolean(at.product && at.stream && at.variant);
  const where = {
    product: at.product ?? "",
    stream: at.stream ?? "",
    variant: at.variant ?? "",
  };
  // Back to the first page whenever the build changes. The offset is in the
  // query key, so carrying page nine onto a build with two pages asks for rows
  // that are not there — and the empty answer draws as "nothing is known about
  // this build yet", with the footer inside the rows branch and so no way back.
  const showing = `${where.product}\u0000${where.stream}\u0000${where.variant}`;
  const [shown, setShown] = useState(showing);
  if (shown !== showing) {
    setShown(showing);
    setOffset(0);
  }

  const register = useQuery({
    enabled: whole,
    queryKey: ["register", where, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/register", {
          params: { path: where, query: { limit: PAGE, offset } },
        }),
      ),
  });

  const rows = register.data?.items ?? [];
  const total = register.data?.total ?? 0;

  return (
    <Sheet
      settled={register.isSuccess}
      name="Disposition register"
      answers="every vulnerability known in one build, and what became of it."
    >
      {!whole ? (
        <section className="panel">
          <Empty
            title="Pick a product, a branch or tag, and a variant."
            detail="A register is read against what one build shipped, so it is about one build and no other."
          />
        </section>
      ) : register.isPending ? (
        <Loading />
      ) : register.isError ? (
        <Failed error={register.error} what="The register could not be read." />
      ) : (
        <section className="panel">
          <h3>
            {total.toLocaleString()} {total === 1 ? "row" : "rows"}
          </h3>
          <p className="hint" style={{ marginTop: 0 }}>
            One row per issue and place, unfolded. Everything the build carries, decided or not and
            open or closed: <b>no triage line is applied</b>. The whole of it as a file —{" "}
            <a href={fileAt(where, "csv")}>CSV</a> · <a href={fileAt(where, "json")}>JSON</a>.
          </p>
          {rows.length === 0 ? (
            <Empty
              title={total > 0 ? "Nothing on this page." : "Nothing is known about this build yet."}
              detail={
                total > 0
                  ? "The register has rows before this point."
                  : "No scan has been applied to it, or nothing here is yours to read."
              }
            />
          ) : (
            <>
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Issue</th>
                      <th>Component</th>
                      <th>Pulled in by</th>
                      <th>State</th>
                      <th>Claimed</th>
                      <th>Proposed</th>
                      <th>Agreed</th>
                      <th>Due</th>
                      <th>Met</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={`${row.vulnerability} ${row.place}`} className="row">
                        <td>
                          <Severity word={row.severity} />{" "}
                          <span className="id">{row.vulnerability}</span>
                        </td>
                        <td className="id">
                          {row.component} <span className="hint">{row.version}</span>
                        </td>
                        {/* The name, not the identity. A place identity is
                            derived from content, so it correlates two rows and
                            tells nobody where anything is — a column of
                            sixty-four hex characters is noise on a page
                            somebody reads. */}
                        <td className="id">
                          {row.consumer || <span className="hint">the build itself</span>}
                        </td>
                        <td>
                          {/* The row an auditor is looking for is the one
                              every other report leaves out — and the other
                              three states are said in words too. One arm was
                              written and the rest fell through to the raw wire
                              token, so a register read "waiting", "agreed" and
                              "lapsed" in the vocabulary of the database. A
                              fifth state still shows as it arrived, which is
                              visible rather than blank. */}
                          <RegisterState state={row.state} />
                        </td>
                        <td>
                          {row.outcome ? (
                            <Outcome outcome={row.outcome} />
                          ) : (
                            <span className="hint">—</span>
                          )}
                        </td>
                        <td>
                          {row.proposed_by ? (
                            <>
                              <span className="id">{row.proposed_by}</span>{" "}
                              <span className="hint">{on(row.proposed_at)}</span>
                            </>
                          ) : (
                            <span className="hint">—</span>
                          )}
                        </td>
                        <td>
                          {row.approved_by ? (
                            <>
                              <span className="id">{row.approved_by}</span>{" "}
                              <span className="hint">{on(row.approved_at)}</span>
                              {/* Given for the claim this one re-affirms, so
                                  the name above read those words. */}
                              {row.agreement_carried && <span className="hint"> · carried</span>}
                            </>
                          ) : (
                            <span className="hint">—</span>
                          )}
                        </td>
                        <td>{row.due ? on(row.due) : <span className="hint">none</span>}</td>
                        <td>
                          {/* Answerable only for something that closed: an open
                              row has not missed its deadline, it has not
                              reached the end of the question. */}
                          {row.met === undefined ? (
                            <span className="hint">—</span>
                          ) : row.met ? (
                            <span className="state closed">met</span>
                          ) : (
                            <span className="state open">missed</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
            </>
          )}
          {/* Outside the rows branch: a page past the end has no rows, and a
              footer that only draws where there are rows leaves nowhere to
              press Previous from. */}
          <div className="noprint">
            <Paged
              shown={rows.length}
              total={total}
              offset={offset}
              limit={PAGE}
              onGo={setOffset}
              what="listed"
            />
          </div>
        </section>
      )}
    </Sheet>
  );
}

// What stands at one place, in the words the sheet uses.
//
// Four states, and a state this does not know shown as it arrived. A register
// is read by somebody checking the record against what shipped, so a column of
// wire tokens is the tool showing its storage rather than answering.
function RegisterState({ state }: { state?: string }) {
  switch (state) {
    case "undecided":
      return <span className="state open">nobody has said</span>;
    case "lapsed":
      return <span className="state lapsed">no longer stands</span>;
    case "waiting":
      return <span className="state waiting">waiting for a second person</span>;
    case "agreed":
      return <span className="state agreed">agreed</span>;
    default:
      return state ? <span className="hint">{state}</span> : null;
  }
}

// Where the file comes from. A link somebody follows rather than a request
// this page makes, so the browser fetches it with the session it already has.
function fileAt(at: { product: string; stream: string; variant: string }, format: string): string {
  return (
    `/v1/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}/register.${format}`
  );
}
