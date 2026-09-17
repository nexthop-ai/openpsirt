import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useQuery } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { usePaging } from "./list";
import { notYours, unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Markdown } from "../ui/Markdown";
import { Because, labeled } from "../ui/Outcome";
import { Paged } from "../ui/Paged";
import { Choices } from "../ui/Choices";
import { Wide } from "../ui/Wide";
import { coveringPeriod, stated } from "./reports/Window";

// How much of the record one page holds. The server's own ceiling is five
// hundred; a page is what somebody reads, and the rest is a click away rather
// than behind a narrower search.
const PAGE = 100;

type Judged = Body<"JudgedBody">;

// Nothing ticked is every judgment, so there is no entry for it: "any" is an
// empty set rather than a value somebody picks.
const OUTCOMES = [
  ["not-applicable", "dismissed — not applicable"],
  ["wont-fix", "dismissed — will not fix"],
  // The fifth outcome, and the one an auditor most wants to check: a claim
  // that a distribution already backported the fix is checkable against the
  // packager's own record, and it was missing from this list while the API
  // took it.
  ["already-fixed", "dismissed — already fixed here"],
  ["deferred", "deferred"],
  // The two that promise work rather than dismissing it. They hide risk until
  // the date they named, which is exactly what an auditor is checking, and the
  // API took them while this list did not offer them.
  ["upgrade-needed", "upgrade planned"],
  ["patch-needed", "backport planned"],
  ["affected", "affected"],
] as const;

// The dismissals, which are the outcomes that require a second person. The
// exception report is asked of one of these, because asked of everything it
// returns a large and entirely legitimate population.
const DISMISSALS = new Set(["not-applicable", "wont-fix", "already-fixed"]);

const STATES = [
  ["approved", "agreed"],
  ["proposed", "waiting"],
  ["lapsed", "lapsed"],
  ["withdrawn", "withdrawn"],
] as const;

// The record of what was judged, for somebody auditing it.
//
// Its own screen rather than a filter on the findings list, because the unit
// differs: a finding is a thing that might be wrong, and this is a judgment
// somebody made about one — with who made it, who agreed, and when each
// happened. The findings list answers "what is open"; this answers "what did
// you decide, and on whose say-so".
//
// **Built to be printed.** An auditor takes a copy away, so the page prints as
// the record rather than as a screenshot of an application: the shell, the
// controls and the links go, a header states what was asked for and when it was
// taken, and a judgment does not break across a page.
export function Audit() {
  const [params, setParams] = useSearchParams();
  // Repeated in the address rather than one value each, because "dismissed or
  // deferred" and "waiting or sent back" are questions a single value cannot
  // ask. The findings list already reads its filters this way.
  const products = params.getAll("product").filter(Boolean);
  const outcomes = params.getAll("outcome").filter(Boolean);
  const states = params.getAll("state").filter(Boolean);
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  const alone = params.get("alone") === "true";
  // A page of the record rather than a cap on it. It asked for five hundred
  // and said "narrow the dates to print the rest", which is a search dressed
  // as an answer: an auditor reading a year cannot narrow to something they
  // have not read yet, and the rows past the cap were unreachable from this
  // screen entirely.

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    // A narrowed list starts at its own beginning: keeping the offset lands
    // somebody on page seven of a list that now has two.
    next.delete("offset");
    setParams(next);
  }

  // The same, for a question that takes several answers: every value under one
  // key, replaced together.
  function setMany(key: string, values: string[]) {
    const next = new URLSearchParams(params);
    next.delete(key);
    for (const value of values) next.append(key, value);
    next.delete("offset");
    setParams(next);
  }

  // The shared handler, with the record's own addition: this list is long
  // and paging it from the foot leaves the reader at the foot of the next
  // page, looking at rows they have to scroll up to reach.
  const { offset, go: paged } = usePaging();
  function go(to: number) {
    paged(to);
    window.scrollTo({ top: 0 });
  }

  const declared = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const record = useQuery({
    queryKey: ["audit", products, outcomes, states, from, to, alone, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/audit", {
          params: {
            query: {
              limit: PAGE,
              ...(offset > 0 ? { offset } : {}),
              ...(products.length > 0 ? { product: products } : {}),
              ...(outcomes.length > 0
                ? {
                    outcome: outcomes as (
                      | "affected"
                      | "not-applicable"
                      | "deferred"
                      | "wont-fix"
                      | "already-fixed"
                      | "upgrade-needed"
                      | "patch-needed"
                    )[],
                  }
                : {}),
              ...(alone ? { alone: true } : {}),
              ...(states.length > 0
                ? { state: states as ("proposed" | "approved" | "withdrawn" | "lapsed")[] }
                : {}),
              ...(from ? { from } : {}),
              ...(to ? { to } : {}),
            },
          },
        }),
      ),
  });

  const rows = record.data?.items ?? [];
  const total = record.data?.total ?? 0;
  // Said on the printed copy, because a page of judgments with no statement of
  // what was asked for is a page nobody can check.
  // Every value, not the first of them: a printed sheet saying "dismissed —
  // not applicable" over rows that also hold deferrals is a sheet nobody can
  // check against anything.
  const said = (options: readonly (readonly [string, string])[], chosen: string[]) =>
    chosen.map((value) => options.find(([v]) => v === value)?.[1] ?? value).join(", ");
  // The exception report reads as "this should be empty" only where every
  // outcome asked for is a dismissal. Mixed with a deferral it returns a large
  // and entirely legitimate population, and saying otherwise over those rows
  // would be telling an auditor a control had failed when it had not.
  const onlyDismissals = outcomes.length > 0 && outcomes.every((each) => DISMISSALS.has(each));
  const asked = [
    products.length > 0 ? products.join(", ") : "every product you can see",
    said(OUTCOMES, outcomes),
    said(STATES, states),
    from || to ? `proposed ${from || "at any time"} to ${to || "now"}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <>
      <div className="screen-head">
        <h2>
          The record <span className="n">{total.toLocaleString()}</span>
        </h2>
        <p>Every judgment made, with who made it, who agreed, and when.</p>
        <span style={{ marginLeft: "auto" }} className="noprint">
          {/* The same answer as a file, narrowed the same way. An
              auditor is given a document rather than a screen, and this was
              copied out by hand. The filters travel in the address, so the
              file is this page's own address with a suffix. */}
          <a className="btn quiet" href={recordAt(params, "csv")}>
            CSV
          </a>{" "}
          <a className="btn quiet" href={recordAt(params, "json")}>
            JSON
          </a>{" "}
          <button type="button" className="btn" onClick={() => window.print()}>
            Print
          </button>
        </span>
      </div>

      <div className="filters noprint">
        {/* Three questions that take several answers each. An auditor asks
            "dismissed or deferred" and "waiting or sent back"; a dropdown
            holding one value offered those as two lists to read in turn. */}
        <Choices
          label="Product"
          anything="All products"
          options={(declared.data?.items ?? []).map(
            (each) => [each.name, each.display_name || each.name] as const,
          )}
          chosen={products}
          onChange={(chosen) => setMany("product", chosen)}
        />
        <Choices
          label="Judgment"
          anything="Every judgment"
          options={OUTCOMES}
          chosen={outcomes}
          onChange={(chosen) => setMany("outcome", chosen)}
        />
        <Choices
          label="State"
          anything="Any state"
          options={STATES}
          chosen={states}
          onChange={(chosen) => setMany("state", chosen)}
        />
        {/* The exception report. Asked of everything it returns a
            large and legitimate population — an outcome that hides nothing
            needs no second person — so the screen says what it is for and
            says so loudest when it is asked of a dismissal, where the answer
            should be nothing. */}
        <label className="field">
          <span>Second person</span>
          <select
            value={alone ? "alone" : ""}
            onChange={(e) => set("alone", e.target.value ? "true" : "")}
          >
            <option value="">Any</option>
            <option value="alone">No second person agreed</option>
          </select>
        </label>
        <label className="field">
          <span>Proposed from</span>
          <input type="date" value={from} onChange={(e) => set("from", e.target.value)} />
        </label>
        <label className="field">
          <span>to</span>
          <input type="date" value={to} onChange={(e) => set("to", e.target.value)} />
        </label>
      </div>

      {/* Only on paper. A printed record has to say what it is a record of and
          when it was taken, or nobody reading it later can check it. */}
      <div className="printhead">
        <h1>OpenPSIRT — record of judgments</h1>
        <p>
          {asked} · {total.toLocaleString()} {total === 1 ? "judgment" : "judgments"} · taken{" "}
          {new Date().toISOString().slice(0, 16).replace("T", " ")}Z
        </p>
        {/* Which of them this sheet holds. A printed page that says "1,842
            judgments" over a hundred rows is a page nobody can check against
            anything, and the number is the one an auditor quotes. */}
        {total > rows.length && (
          <p>
            This sheet: {(offset + 1).toLocaleString()} to{" "}
            {Math.min(offset + rows.length, total).toLocaleString()}.
          </p>
        )}
      </div>

      {record.isPending ? (
        <Loading />
      ) : record.isError ? (
        <Failed error={record.error} what="The record could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title={
            alone && onlyDismissals
              ? "No dismissal stands on one person's say-so."
              : "No judgment matches that."
          }
          detail={
            alone && onlyDismissals
              ? "Every dismissal requires a second person. This checks the record."
              : "Widen the dates, or clear the filters."
          }
        />
      ) : (
        <>
          {alone && onlyDismissals && (
            <p className="hint">Dismissals with no standing second approval. Read them.</p>
          )}
          {alone && !onlyDismissals && (
            <p className="hint">
              Judgments one person made. Most are allowed. Narrow to a dismissal for the answer that
              should be empty.
            </p>
          )}
          {rows.map((row) => (
            <Judgment key={row.id} row={row} />
          ))}
          {/* Printed copies carry the page they are of, because a page of
              judgments that does not say which page it is cannot be checked
              against anything. */}
          <div className="noprint">
            <Paged
              shown={rows.length}
              total={total}
              offset={offset}
              limit={PAGE}
              onGo={go}
              what="listed"
            />
          </div>
        </>
      )}

      <Administered />
    </>
  );
}

// What somebody changed about how this deployment works.
//
// Beside the record rather than on a screen of its own, because it is the same
// question one layer up: the deadline windows, the triage floor and a support
// date each silently rewrite what the record above says, and reading the
// judgments without being able to see who moved the ground under them is
// reading half of it.
function Administered() {
  const [params] = useSearchParams();
  // The period the screen is already reading, rather than a second one of its
  // own. Who moved the ground under a set of judgments is the same question
  // over the same stretch, and two date controls on one screen is two answers
  // to it.
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  // How many rows are shown, rather than an offset: the newest first is the
  // order, and asking for the next page of a list that only grows at the top
  // is how a row is seen twice or not at all.
  const [showing, setShowing] = useState(50);
  const changes = useQuery({
    queryKey: ["administered", from, to, showing],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/administration/changes", {
          params: {
            query: {
              limit: showing,
              ...(from ? { from } : {}),
              ...(to ? { to } : {}),
            },
          },
        }),
      ),
    // An administrator's or an auditor's screen; anybody else is refused and
    // the section is simply absent for them.
    retry: false,
  });
  const rows = changes.data?.items ?? [];
  // Absent for somebody who is not an administrator, which is the refusal this
  // section expects. A read that failed for any other reason is said, because
  // an audit screen silently missing half of what it is for is the one place
  // a quiet absence costs the most.
  if (changes.isError) {
    return notYours(changes.error) ? null : (
      <div style={{ marginTop: 24 }}>
        <h3>Change history</h3>
        <Failed error={changes.error} what="The change history could not be read." />
      </div>
    );
  }
  if (rows.length === 0 && showing === 50) return null;

  return (
    <div style={{ marginTop: 24 }} id="changes">
      <div className="screen-head">
        <h3>Change history</h3>
        <span style={{ marginLeft: "auto" }} className="noprint">
          {/* The record an access review is written from, as a file. It was
              capped at fifty rows on a screen and could not leave it. */}
          <a className="btn quiet" href={changesAt(params, "csv")}>
            CSV
          </a>{" "}
          <a className="btn quiet" href={changesAt(params, "json")}>
            JSON
          </a>
        </span>
      </div>
      <p className="hint">
        Settings, roles, support dates, credentials, accounts and teams, with what each held before.
        {stated({ from, to }) ? ` Over ${coveringPeriod({ from, to }, 0)}.` : ""}
      </p>
      <Wide>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              <th>What</th>
              <th>Was</th>
              <th>Became</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={`${row.at} ${row.about} ${i}`}>
                <td className="id">{(row.at ?? "").slice(0, 16).replace("T", " ")}</td>
                <td>{row.by}</td>
                <td>
                  <span className="hint">{row.kind}</span> {row.about}
                </td>
                <td>{row.unset ? <span className="hint">unset</span> : row.was}</td>
                <td>{row.cleared ? <span className="hint">cleared</span> : row.became}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
      {(changes.data?.total ?? 0) > rows.length && (
        <p className="hint noprint">
          Showing the newest {rows.length.toLocaleString()} of{" "}
          {(changes.data?.total ?? 0).toLocaleString()}.{" "}
          <button
            type="button"
            className="btn quiet"
            disabled={changes.isFetching}
            onClick={() => setShowing((shown) => shown + 100)}
          >
            Show more
          </button>
        </p>
      )}
    </div>
  );
}

// Where the change history comes from as a file, built the way the record's
// own link is: the screen's period straight from the address, so the file and
// the section it was taken from cannot disagree about the stretch.
function changesAt(params: URLSearchParams, format: string): string {
  const asked = new URLSearchParams();
  for (const name of ["from", "to"]) {
    const value = params.get(name);
    if (value) asked.set(name, value);
  }
  const query = asked.toString();
  return `/v1/administration/changes.${format}${query ? `?${query}` : ""}`;
}

function Judgment({ row }: { row: Judged }) {
  const standing = row.approvals?.filter((a) => !a.withdrawn_at) ?? [];
  const withdrawn = row.approvals?.filter((a) => a.withdrawn_at) ?? [];

  return (
    <div className="judgment">
      <header>
        {/* A row that names a judgment and cannot be opened is one an auditor
            reads and then hunts for by hand. It prints as its own text, so the
            paper record is unchanged. */}
        <Link className="id" to={`/decisions/${row.id}`}>
          {row.issue}
        </Link>
        <span className={`claimed ${row.outcome}`}>
          {/* The word, not the token. The justification beside it has been said
              in words for a while and this had not caught up, so a record read
              "upgrade-needed · The vulnerable code never runs". */}
          <b>{labeled(row.outcome)}</b>
          {row.justification && (
            <span className="why">
              <Because code={row.justification} />
            </span>
          )}
        </span>
        <span className={`state ${row.standing ? "agreed" : "open"}`}>
          {row.standing ? "stands" : row.state}
        </span>
      </header>

      <dl className="facts">
        <dt>About</dt>
        <dd>
          <span className="id">{row.component}</span>{" "}
          <span className="id" style={{ color: "var(--faint)" }}>
            {row.version}
          </span>
          {row.consumer && (
            <>
              {" "}
              in <span className="id">{row.consumer}</span>
            </>
          )}{" "}
          · {row.product}
        </dd>

        <dt>Proposed</dt>
        <dd>
          <b>{row.proposed_by}</b> · {on(row.proposed_at)}
        </dd>

        <dt>Approved</dt>
        <dd>
          {standing.length === 0 ? (
            <span className="hint">nobody yet</span>
          ) : (
            standing.map((a, i) => (
              <span key={i}>
                {i > 0 && ", "}
                <b>{a.by}</b> · {on(a.at)}
                {/* They read the earlier claim's words, not these. Shown
                    because a name with no mark beside it says they read
                    what is on the screen above it. */}
                {a.carried && <span className="hint"> (carried forward)</span>}
              </span>
            ))
          )}
          {/* Two different people is the control, so the record says whether
              this one has it rather than leaving a reader to compare names. */}
          {row.two_people ? (
            <span className="state agreed" style={{ marginLeft: 8 }}>
              two people
            </span>
          ) : (
            standing.length > 0 && (
              <span className="state lapsed" style={{ marginLeft: 8 }}>
                same person
              </span>
            )
          )}
        </dd>

        {withdrawn.length > 0 && (
          <>
            <dt>Taken back</dt>
            <dd>
              {withdrawn.map((a, i) => (
                <span key={i}>
                  {i > 0 && ", "}
                  <b>{a.by}</b> agreed {on(a.at)}
                  {a.carried && " (carried forward)"}, withdrawn {on(a.withdrawn_at)}
                </span>
              ))}
            </dd>
          </>
        )}

        {row.deferred_until && (
          <>
            <dt>Until</dt>
            <dd>{row.deferred_until}</dd>
          </>
        )}

        {/* The one field that checks an already-fixed claim, and it was
            returned and never drawn: what the packager's own record has to
            agree with. */}
        {row.fixed_version && (
          <>
            <dt>Fixed in</dt>
            <dd>
              <span className="id">{row.fixed_version}</span>
            </dd>
          </>
        )}

        {row.mitigation && (
          <>
            <dt>Control named</dt>
            <dd>
              {row.mitigation}
              {/* Said here rather than left implicit. This is the one claim
                  nothing here can notice going away. */}
              <span className="hint"> — nothing here notices this being removed</span>
            </dd>
          </>
        )}

        {row.ended_at && (
          <>
            <dt>Stopped applying</dt>
            <dd>
              {on(row.ended_at)} · {row.state}
            </dd>
          </>
        )}
      </dl>

      <div className="reasoning">
        <Markdown source={row.reasoning ?? ""} />
      </div>
    </div>
  );
}

// Where the record comes from as a file. Built here rather than by the
// generated client because it is a link somebody follows, not a request this
// page makes: the browser fetches it with the session it already has.
//
// The screen's own filters are the file's, straight from the address, so a
// narrowed screen and the file taken from it cannot disagree about what was
// asked for.
function recordAt(params: URLSearchParams, format: string): string {
  const asked = new URLSearchParams(params);
  asked.delete("offset");
  const query = asked.toString();
  return `/v1/audit.${format}${query ? `?${query}` : ""}`;
}
