// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Loading } from "../ui/Loading";
import { initials } from "../ui/initials";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { scopeQuery, useScope } from "../app/scope";
import { useWho } from "../app/session";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Severity, Exploited, Incident } from "../ui/Severity";
import { useRowOpener } from "../ui/opens";
import { Wide } from "../ui/Wide";
import { Paged } from "../ui/Paged";
import { usePaging } from "./list";
import { findingOf, vulnerabilityReportAt, codeFindingAt, codeFindingsAt } from "../app/routes";
import { useHandBack, useHeldReports } from "../api/intake";
import { counted, holding } from "../app/families";
import { useOwnWork, type WorkFamily } from "../app/ownWork";
import { HeldLine } from "../ui/HeldLine";
import { on } from "../ui/when";

// One page of what somebody holds. The answer carries a total, so this is a
// page rather than a cap and the footer pages through the rest.
const PAGE = 50;

// Assignments: what is running out of time undecided, and what each person
// holds. What nobody holds has its own entry in the rail, which opens each
// family's list of unheld work, so this screen links across rather than
// drawing a list twice.
//
// Work assigned to somebody who has gone is invisible twice over: not in the
// shared queue because it is assigned, and not in anybody's list because they
// are not here. Nothing tells us somebody left, so releasing their work is an
// action rather than something the tool discovers.
export function Assignments() {
  const [params, setParams] = useSearchParams();
  const who = useWho();
  const at = useScope();
  const scope = scopeQuery(at);
  // Who else holds what is counted in findings of both families, narrowed to
  // the reader. A reader of neither at the scope would read "nobody else is
  // holding anything", so the tab is drawn, and its totals asked for, only
  // where one family is read; what the reader holds is theirs and always
  // counted.
  const dependencies = holding(who.data, "dependency", scope.product);
  const code = holding(who.data, "code", scope.product);
  const othersCounted = counted(dependencies) || counted(code);
  const tab = othersCounted ? (params.get("tab") ?? "due") : "due";
  const { offset, go: goTo } = usePaging();
  // What the reader holds is two lists, one per family, each paged on its
  // own: a rule at a place and an advisory at a component are different
  // units, so neither page nor total spans both.
  const codePaging = usePaging(CODE_OFFSET);
  // The product the picker is on, which is the whole of what this answers for:
  // somebody scoped to one product is shown and counted work from that product
  // alone.
  const holdings = useQuery({
    queryKey: ["holdings", scope.product ?? ""],
    enabled: othersCounted,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/assignments", {
          params: { query: scope.product ? { product: scope.product } : {} },
        }),
      ),
  });
  // Whose work is being looked at on the second tab. Empty is the roll-up of
  // everybody; a name is that holder's list.
  //
  // The kind of holder, because a team is not a person. Work goes to a team by an
  // assignment rule and by an assignment naming one, and the person's route
  // resolves an identity, so a team's list is read from the team's own route.
  const person = params.get("person") ?? "";
  const team = params.get("team") ?? "";
  const holder = team || person;
  const mine = [
    useOwnWork(who.data, "dependency", scope, { limit: PAGE, offset }),
    useOwnWork(who.data, "code", scope, { limit: PAGE, offset: codePaging.offset }),
  ];
  // Another holder's list is drawn on the Assigned to others tab alone, so it
  // is asked only there: a kept link naming somebody, followed by a reader the
  // tab is not drawn for, asks nothing.
  const theirs = useQuery({
    enabled: tab === "people" && person !== "",
    queryKey: ["assigned", person, scope, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people/{identity}/assignments", {
          params: { path: { identity: person }, query: { limit: PAGE, offset, ...scope } },
        }),
      ),
  });
  const theTeams = useQuery({
    enabled: tab === "people" && team !== "",
    queryKey: ["team-assigned", team, scope, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/teams/{team}/assignments", {
          params: { path: { team }, query: { limit: PAGE, offset, ...scope } },
        }),
      ),
  });
  const held = team ? theTeams : theirs;

  // Every change of tab or holder is another list, which starts at its own
  // beginning: a page into one list is past the end of a shorter one.
  function go(next: string) {
    const now = new URLSearchParams(params);
    if (next === "due") now.delete("tab");
    else now.set("tab", next);
    now.delete("offset");
    now.delete(CODE_OFFSET);
    setParams(now);
  }

  const peopleRows = holdings.data?.items ?? [];
  // Nobody's work appears on this screen. What is waiting for nobody is its
  // own screen and its own question — mixed in here it makes "assignments" a
  // list of things that are not assigned, which is the one thing it must not
  // be.
  // A team's name is not reserved against identities, so a team row is never
  // the viewer's own.
  const own = (row: { person?: string; team?: boolean }) =>
    !row.team && row.person === who.data?.identity;
  const others = peopleRows.filter((row) => !own(row));
  // Code findings are left out of the findings list, so the unheld ones of the
  // product in scope are linked where this screen points at unheld work.
  const codeFindingsIn = scope.product && counted(code) ? scope.product : undefined;

  return (
    <>
      <div className="screen-head">
        <h2>Assignments</h2>
        <p>
          {scope.product
            ? [scope.product, scope.branch_or_tag, scope.variant].filter(Boolean).join(" · ")
            : "Across every product you can see"}
        </p>
      </div>

      <div className="tabs2">
        <button
          type="button"
          className="tab2 urgent"
          aria-selected={tab === "due"}
          onClick={() => go("due")}
        >
          Assigned to me
        </button>
        {othersCounted && (
          <button
            type="button"
            className="tab2"
            aria-selected={tab === "people"}
            onClick={() => go("people")}
          >
            Assigned to others <span className="n">{others.length}</span>
          </button>
        )}
      </div>

      {/* Who else holds what is said to be of the families read here. On
          the reader's own tab each family says it for itself. */}
      {tab === "people" && (
        <>
          <HeldLine at={dependencies} />
          <HeldLine at={code} />
        </>
      )}

      {/* Said rather than discovered. Who holds what is answered per product,
          so a branch or a variant in the picker narrows the other two tabs and
          not this one. */}
      {tab === "people" && (scope.branch_or_tag || scope.variant) && (
        <p className="hint">
          Across every build of {scope.product}. The branch and the variant do not narrow who holds
          what.
        </p>
      )}

      {tab === "due" ? (
        <>
          {/* A reader of neither family anywhere, holding nothing: both
              lists answered empty, which is the one thing there is to say. */}
          {mine.every(
            (work) => work.at.held === "nowhere" && work.query.isSuccess && !work.drawn,
          ) && (
            <Empty
              title="Nothing is assigned to you."
              detail="Work somebody hands you appears here."
            />
          )}
          {mine.map((work) => (
            <OwnFamily
              key={work.family}
              work={work}
              onGo={work.family === "code" ? codePaging.go : goTo}
              offset={work.family === "code" ? codePaging.offset : offset}
            />
          ))}
          <Reports whose={{ person: "me" }} product={scope.product} />
        </>
      ) : holder ? (
        <>
          <div className="filters" style={{ marginBottom: 10 }}>
            <button
              type="button"
              className="linkish"
              onClick={() => {
                const now = new URLSearchParams(params);
                now.delete("person");
                now.delete("team");
                now.delete("offset");
                setParams(now);
              }}
            >
              ← Everybody
            </button>
            <span className="hint">
              What <b>{holder}</b> is dealing with{team && " · team queue"}
            </span>
          </div>
          <Held
            rows={held.data?.items ?? []}
            total={held.data?.total ?? 0}
            query={held}
            offset={offset}
            onGo={goTo}
            empty={team ? "The team is not holding anything." : "They are not holding anything."}
            detail="Either it has been decided, or somebody handed it back."
          />
          <Reports whose={team ? { team } : { person }} product={scope.product} />
        </>
      ) : (
        <ByPerson
          rows={others}
          query={holdings}
          codeFindingsIn={codeFindingsIn}
          onPick={(name, isTeam) => {
            const now = new URLSearchParams(params);
            now.delete("person");
            now.delete("team");
            now.delete("offset");
            now.set(isTeam ? "team" : "person", name);
            setParams(now);
          }}
        />
      )}
      {tab === "people" && !holder && (
        <Reports whose="nobody" product={scope.product} title="Reports nobody holds" />
      )}
    </>
  );
}

// The parameter the reader's own code findings are paged by, beside the
// dependency findings' `offset`.
const CODE_OFFSET = "code_offset";

const OWN: Record<WorkFamily, { title: string; empty: string; detail: string }> = {
  dependency: {
    title: "Dependency findings",
    empty: "No dependency findings are assigned to you.",
    detail: "Work you take on from a finding, or that somebody hands you, appears here.",
  },
  code: {
    title: "Code findings",
    empty: "No code findings are assigned to you.",
    detail: "Code findings you take on from the security testing queue appear here.",
  },
};

// One family of the reader's own work: its count and its rows where the
// count says what it counts, and the line saying why not where it does not.
function OwnFamily({
  work,
  offset,
  onGo,
}: {
  work: ReturnType<typeof useOwnWork>;
  offset: number;
  onGo: (offset: number) => void;
}) {
  const said = OWN[work.family];
  if (!work.drawn) {
    // Held nowhere, a family the reader holds nothing of is not drawn.
    if (work.at.held === "nowhere") return null;
    return (
      <>
        <h3 style={{ margin: "18px 0 8px" }}>{said.title}</h3>
        <HeldLine at={work.at} />
      </>
    );
  }
  return (
    <>
      <h3 style={{ margin: "18px 0 8px" }}>
        {said.title} <span className="n">{(work.query.data?.total ?? 0).toLocaleString()}</span>
      </h3>
      <HeldLine at={work.at} />
      <Held
        rows={work.query.data?.items ?? []}
        total={work.query.data?.total ?? 0}
        query={work.query}
        offset={offset}
        onGo={onGo}
        empty={said.empty}
        detail={said.detail}
      />
    </>
  );
}

// Open vulnerability reports somebody holds, or nobody does. Drawn only where
// there are any, because most people read no reports at all.
function Reports({
  whose,
  product,
  title = "Vulnerability reports",
}: {
  whose: { person: string } | { team: string } | "nobody";
  product?: string;
  title?: string;
}) {
  const opener = useRowOpener();
  const held = useHeldReports(whose, product);
  if (held.isPending) return null;
  if (held.isError) {
    return <Failed error={held.error} what="The vulnerability reports could not be read." />;
  }
  const rows = held.data.items ?? [];
  const total = held.data.total ?? rows.length;
  if (rows.length === 0) return null;
  return (
    <>
      <h3 style={{ margin: "18px 0 8px" }}>
        {title} <span className="n">{total.toLocaleString()}</span>
      </h3>
      <Wide>
        <table>
          <thead>
            <tr>
              <th>Report</th>
              <th>Product</th>
              <th>From</th>
              <th>Arrived</th>
              {whose !== "nobody" && <th>Held by</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const to = vulnerabilityReportAt(row.product, row.reference);
              return (
                <tr
                  key={`${row.product} ${row.reference}`}
                  className="row opens"
                  onClick={opener(to)}
                >
                  <td>
                    <Link className="id" style={{ whiteSpace: "nowrap" }} to={to}>
                      {row.reference}
                    </Link>
                    {row.title && <span className="hint"> · {row.title}</span>}
                    {row.waiting && <span className="hint"> · ruling waiting</span>}
                  </td>
                  <td className="hint">{row.product}</td>
                  <td>{row.reported_by || <span className="hint">—</span>}</td>
                  <td className="hint">{row.received || on(row.recorded_at)}</td>
                  {whose !== "nobody" && (
                    <td className="hint">
                      {row.assigned_to_name || row.assigned_to}
                      {row.assigned_team && " · team queue"}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </Wide>
      {total > rows.length && (
        <p className="hint">
          The {rows.length} oldest of {total.toLocaleString()}.
        </p>
      )}
    </>
  );
}

type Query = { isPending: boolean; isError: boolean; error: unknown };

function ByPerson({
  rows,
  query,
  codeFindingsIn,
  onPick,
}: {
  rows: Body<"HoldingBody">[];
  query: Query;
  codeFindingsIn?: string;
  onPick: (name: string, team: boolean) => void;
}) {
  const release = useHandBack();

  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="The holdings could not be read." />;
  }
  if (rows.length === 0) {
    return (
      <Empty
        title="Nobody else is holding anything."
        detail="What is waiting for nobody is under Unassigned; this one is about work somebody has taken on."
      >
        {codeFindingsIn && (
          <Link to={codeFindingsAt(codeFindingsIn, { assigned: "nobody" })}>
            Unassigned code findings in {codeFindingsIn}
          </Link>
        )}
      </Empty>
    );
  }

  return (
    <>
      {release.error != null && (
        <Failed error={release.error} what="Their work could not be released." />
      )}
      <Wide>
        <table>
          <thead>
            <tr>
              <th>Assignee</th>
              <th className="num">Open</th>
              <th className="num">Findings</th>
              <th className="num">Overdue</th>
              <th className="num">Reports</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.team ? "t" : "p"}:${row.person}`} className="row">
                <td>
                  <button
                    type="button"
                    className="linkish"
                    onClick={() => onPick(row.person ?? "", Boolean(row.team))}
                    title="See what they are dealing with"
                  >
                    <span className="who2">
                      {/* A team is a queue rather than a person, and drawing
                          it with somebody's initials says the opposite: work
                          assigned to a team is unheld until somebody takes it. */}
                      <span className="avatar">
                        {row.team ? "◇" : initials(row.person_name || row.person || "")}
                      </span>
                      {row.person_name || row.person}
                      {row.team && <span className="hint"> · team queue</span>}
                    </span>
                  </button>
                </td>
                <td className="num">{(row.open ?? 0).toLocaleString()}</td>
                <td className="num" style={{ color: "var(--faint)" }}>
                  {(row.occurrences ?? 0).toLocaleString()}
                </td>
                <td className="num">
                  {(row.overdue ?? 0) > 0 ? (
                    <span className="due over">{row.overdue}</span>
                  ) : (
                    <span style={{ color: "var(--faint)" }}>0</span>
                  )}
                </td>
                <td className="num">{(row.reports ?? 0).toLocaleString()}</td>
                <td>
                  {/* A team queue is not emptied here. What this calls is a
                      route per person, and a team is not one — so the control
                      says what is true rather than offering an act it never
                      performs. */}
                  <button
                    type="button"
                    className="btn quiet"
                    title={
                      row.team
                        ? "A team queue empties as people take the work, not from here"
                        : "Put everything they hold back into the unassigned list"
                    }
                    disabled={release.isPending || row.team}
                    onClick={() => release.mutate(row.person ?? "")}
                  >
                    Unassign all
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
      <p className="hint" style={{ marginTop: 10 }}>
        <b>Open</b> is one issue in one component. <b>Findings</b> is the rows those cover across
        every build.
      </p>
      <p className="hint" style={{ marginTop: 10 }}>
        Reassign their work manually when somebody leaves.
      </p>
    </>
  );
}

// One person's own work, in the same units as what nobody is dealing with: one
// row per issue in a component in a product, not one per build. The same code
// built several ways is one piece of work and was taken on as one. A static
// analysis code finding is a row of its own, named by its rule, and opens its page.
function Held({
  rows,
  total,
  query,
  offset,
  onGo,
  empty,
  detail,
}: {
  rows: Body<"UnassignedBody">[];
  total: number;
  query: Query;
  offset: number;
  onGo: (offset: number) => void;
  empty: string;
  detail: string;
}) {
  const opener = useRowOpener();
  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="The assigned work could not be read." />;
  }
  if (total === 0) return <Empty title={empty} detail={detail} />;
  // A page past the end of what is held, from an address kept from another
  // list: the way back is the pager rather than a statement that nothing is
  // held.
  if (rows.length === 0) {
    return <Paged shown={0} total={total} offset={offset} limit={PAGE} onGo={onGo} />;
  }

  return (
    <>
      <Wide>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Issue</th>
              <th>Component</th>
              <th>Where</th>
              <th
                className="num"
                title="Each way this component enters the build, judged on its own"
              >
                Occurrences
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const to = row.occurrence
                ? codeFindingAt(
                    {
                      product: row.product,
                      branch_or_tag: row.branch_or_tag,
                      variant: row.variant,
                    },
                    row.occurrence,
                  )
                : findingOf(row);
              return (
                <tr
                  key={`${row.product} ${row.vulnerability} ${row.component} ${row.version} ${row.occurrence ?? ""}`}
                  className="row opens"
                  onClick={opener(to)}
                >
                  <td>
                    <Severity word={row.severity} />
                  </td>
                  <td>
                    <Link to={to} className="id">
                      {row.vulnerability}
                    </Link>{" "}
                    {row.occurrence && <span className="hint">code finding</span>}{" "}
                    <Incident when={row.incident} /> <Exploited when={row.exploited} />
                  </td>
                  <td>
                    <span className="id">{row.component}</span>{" "}
                    <span className="id" style={{ color: "var(--faint)" }}>
                      {row.version}
                    </span>
                  </td>
                  <td className="hint">
                    {row.product_name || row.product}
                    {(row.builds ?? 1) > 1 ? (
                      <> · {row.builds} builds</>
                    ) : (
                      <>
                        {" "}
                        · {row.branch_or_tag_name || row.branch_or_tag} ·{" "}
                        {row.variant_name || row.variant}
                      </>
                    )}
                  </td>
                  <td className="num">{row.occurrences}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Wide>
      <Paged shown={rows.length} total={total} offset={offset} limit={PAGE} onGo={onGo} />
    </>
  );
}
