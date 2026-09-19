import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
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
import { STATES, type Stands, said } from "../../ui/states";
import { Wide } from "../../ui/Wide";

// How much of the register one page holds. The server's own ceiling is five
// hundred; this is what somebody reads before paging, and the file is what
// they take away.
const PAGE = 200;

// Every known vulnerability in one build, and what became of it.
//
// The complement of the record, not a variant of it. The record says what
// was decided; an auditor's first question is what was *known*, decided or not.
// So a row nobody has said anything about is in here, and so is a closed one —
// a register of what is still open answers a different question from the one it
// would appear to answer.
//
// One row per issue and place, unfolded. Every other list here groups,
// because a person reading a list wants the judgment rather than the repetition;
// a register is read against what shipped, and what shipped is places.
//
// It states no triage line because it applies none. Everything in the build
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
  const [params, setParams] = useSearchParams();
  // What the register was narrowed to. In the address, so a narrowed register
  // is something somebody sends rather than describes, and so the file beside
  // it carries the same narrowing.
  const states = params
    .getAll("state")
    .filter((word): word is Stands => (STATES as readonly string[]).includes(word));
  const standing = params.get("standing") === "open";
  const narrowed = {
    ...(states.length > 0 ? { state: states } : {}),
    ...(standing ? { standing: "open" as const } : {}),
  };
  const showing = `${where.product}\u0000${where.stream}\u0000${where.variant}\u0000${params.toString()}`;
  const [shown, setShown] = useState(showing);
  if (shown !== showing) {
    setShown(showing);
    setOffset(0);
  }

  const register = useQuery({
    enabled: whole,
    queryKey: ["register", where, narrowed, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/register", {
          params: {
            path: where,
            query: { limit: PAGE, offset, ...narrowed },
          },
        }),
      ),
  });

  // The narrowing as an address, for the two file links. Written from the same
  // values the query above reads, so the file is the list on screen.
  const asked = new URLSearchParams();
  for (const word of states) asked.append("state", word);
  if (standing) asked.set("standing", "open");

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
          {/* An auditor's questions, asked of the whole answer rather than
              of a narrower one: "what has nobody decided", "what is still
              open". The register applies no triage line whatever is picked
              here, which is what it is for. */}
          <div className="controls">
            <div className="seg" role="group" aria-label="What stands">
              {STATES.map((word) => (
                <button
                  key={word}
                  type="button"
                  aria-pressed={states.includes(word)}
                  onClick={() => {
                    const next = new URLSearchParams(params);
                    const kept = states.includes(word)
                      ? states.filter((each) => each !== word)
                      : [...states, word];
                    next.delete("state");
                    for (const each of kept) next.append("state", each);
                    setParams(next);
                  }}
                >
                  {said(word)}
                </button>
              ))}
            </div>
            <label>
              <input
                type="checkbox"
                checked={standing}
                onChange={(e) => {
                  const next = new URLSearchParams(params);
                  if (e.target.checked) next.set("standing", "open");
                  else next.delete("standing");
                  setParams(next);
                }}
              />{" "}
              Still open
            </label>
          </div>

          <h3>
            {total.toLocaleString()} {total === 1 ? "row" : "rows"}
            {(states.length > 0 || standing) && <span className="hint"> narrowed</span>}
          </h3>
          <p className="hint" style={{ marginTop: 0 }}>
            One row per issue and place, unfolded. Everything the build carries, decided or not and
            open or closed: <b>no triage line is applied</b>. The whole of it as a file —{" "}
            <a href={fileAt(where, "csv", asked)}>CSV</a> ·{" "}
            <a href={fileAt(where, "json", asked)}>JSON</a>, narrowed the same way.
          </p>
          <MeasuredWith measured={register.data?.measured} />
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
                      <th>Closed</th>
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
                          {/* The reason as well as the date. A closure with no
                              reason is refused of whoever writes one, and the
                              words they typed were readable nowhere — so a
                              person was required to say why and nobody could
                              find out. Drawn as plain text: it goes through
                              the submission policy on the way in, like every
                              other field a person types, and what that bounds
                              is what may be rendered rather than what must
                              be — a line in a table is not a document. */}
                          {row.closed ? (
                            <>
                              {on(row.closed)}
                              {row.closed_because && (
                                <span className="hint"> · {row.closed_because}</span>
                              )}
                              {row.closed_note && <div className="hint">{row.closed_note}</div>}
                            </>
                          ) : (
                            <span className="hint">—</span>
                          )}
                        </td>
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

// What the register was measured with.
//
// An auditor reads shipped artifact, inventory, run, scanner and database,
// disposition. The rows are the last link, and without this the page states
// them with nothing behind them — while the inventory that was read is one
// click away and was reachable from nothing.
function MeasuredWith({
  measured,
}: {
  measured?: {
    scan?: number;
    built_at?: string;
    scanner?: string;
    scanner_version?: string;
    database_version?: string;
    ran_at?: string;
    document_hash?: string;
    document_held?: boolean;
    document_at?: string;
  } | null;
}) {
  if (!measured) return null;
  const scanner = [measured.scanner, measured.scanner_version].filter(Boolean).join(" ");
  const built = on(measured.built_at);
  const ran = on(measured.ran_at);
  return (
    <p className="hint" style={{ marginTop: 0 }}>
      Measured from upload <span className="id">{measured.scan}</span>
      {built && ` built ${built}`}
      {scanner && `, scanned by ${scanner}`}
      {measured.database_version && ` against data of ${measured.database_version}`}
      {ran && ` on ${ran}`}.{" "}
      {measured.document_at ? (
        <a href={measured.document_at}>The inventory it read</a>
      ) : (
        // A branch build's contents are let go once read, so the hash is still
        // the record of what arrived and there is nothing to fetch. Said,
        // rather than left looking like an omission.
        <span>The inventory it read is no longer held</span>
      )}
      {measured.document_hash && (
        <>
          {" · "}
          <span className="id" title={measured.document_hash}>
            {measured.document_hash.slice(0, 12)}
          </span>
        </>
      )}
    </p>
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
function fileAt(
  at: { product: string; stream: string; variant: string },
  format: string,
  asked: URLSearchParams,
): string {
  const query = asked.toString();
  return (
    `/v1/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}/register.${format}` +
    (query ? `?${query}` : "")
  );
}
