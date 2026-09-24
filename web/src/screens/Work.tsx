// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loading } from "../ui/Loading";
import { initials } from "../ui/initials";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { scopeQuery, useScope } from "../app/scope";
import { useWho } from "../app/session";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Severity, Exploited } from "../ui/Severity";
import { Wide } from "../ui/Wide";
import { Paged } from "../ui/Paged";
import { pathTo, usePaging } from "./list";

// One page of what somebody holds. The answer carries a total, so this is a
// page rather than a cap and the footer pages through the rest.
const PAGE = 50;

// Assignments: what is running out of time undecided, and what each person
// holds. What nobody holds has its own entry in the rail, which opens the
// findings list under that narrowing, so the third tab links across rather
// than drawing a list twice.
//
// Work assigned to somebody who has gone is invisible twice over: not in the
// shared queue because it is assigned, and not in anybody's list because they
// are not here. Nothing tells us somebody left, so releasing their work is an
// action rather than something the tool discovers.
export function Work() {
  const [params, setParams] = useSearchParams();
  const who = useWho();
  const tab = params.get("tab") ?? "due";

  const at = useScope();
  const scope = scopeQuery(at);
  const { offset, go: goTo } = usePaging();
  // The product the picker is on, which is the whole of what this answers for.
  // It read across every product while the picker was set, so somebody scoped
  // to one was shown and counted work from products they were not looking at.
  const holdings = useQuery({
    queryKey: ["holdings", scope.product ?? ""],
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
  // The kind of holder, because a team is not a person. Work goes to a
  // team by standing rule and by an assignment naming one, and the totals list
  // says a team holds it — but the person's route resolves an identity, so a
  // team's name matched nobody and the screen answered "they are not holding
  // anything" over work it had just counted.
  const person = params.get("person") ?? "";
  const team = params.get("team") ?? "";
  const holder = team || person;
  const mine = useQuery({
    queryKey: ["assigned", "me", scope, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people/{identity}/assignments", {
          params: { path: { identity: "me" }, query: { limit: PAGE, offset, ...scope } },
        }),
      ),
  });
  const theirs = useQuery({
    enabled: person !== "",
    queryKey: ["assigned", person, scope, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people/{identity}/assignments", {
          params: { path: { identity: person }, query: { limit: PAGE, offset, ...scope } },
        }),
      ),
  });
  const theTeams = useQuery({
    enabled: team !== "",
    queryKey: ["team-assigned", team, scope, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/teams/{team}/assignments", {
          params: { path: { team }, query: { limit: PAGE, offset, ...scope } },
        }),
      ),
  });
  const held = team ? theTeams : theirs;

  function go(next: string) {
    const now = new URLSearchParams(params);
    if (next === "due") now.delete("tab");
    else now.set("tab", next);
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
  const myCount = peopleRows.find(own)?.open ?? 0;

  return (
    <>
      <div className="screen-head">
        <h2>Assignments</h2>
        <p>
          {scope.product
            ? [scope.product, scope.stream, scope.variant].filter(Boolean).join(" · ")
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
          Assigned to me <span className="n">{(mine.data?.total ?? myCount).toLocaleString()}</span>
        </button>
        <button
          type="button"
          className="tab2"
          aria-selected={tab === "people"}
          onClick={() => go("people")}
        >
          Assigned to others <span className="n">{others.length}</span>
        </button>
      </div>

      {/* Said rather than discovered. Who holds what is answered per product,
          so a branch or a variant in the picker narrows the other two tabs and
          not this one. */}
      {tab === "people" && (scope.stream || scope.variant) && (
        <p className="hint">
          Across every build of {scope.product}. The branch and the variant do not narrow who holds
          what.
        </p>
      )}

      {tab === "due" ? (
        <Held
          rows={mine.data?.items ?? []}
          total={mine.data?.total ?? 0}
          query={mine}
          offset={offset}
          onGo={goTo}
          empty="Nothing is assigned to you."
          detail="Work you take on from a finding, or that somebody hands you, appears here."
        />
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
        </>
      ) : (
        <ByPerson
          rows={others}
          query={holdings}
          onPick={(name, isTeam) => {
            const now = new URLSearchParams(params);
            now.delete("person");
            now.delete("team");
            now.set(isTeam ? "team" : "person", name);
            setParams(now);
          }}
        />
      )}
    </>
  );
}

type Query = { isPending: boolean; isError: boolean; error: unknown };

function ByPerson({
  rows,
  query,
  onPick,
}: {
  rows: Body<"HoldingBody">[];
  query: Query;
  onPick: (name: string, team: boolean) => void;
}) {
  const queries = useQueryClient();
  const release = useMutation({
    mutationFn: async (identity: string) =>
      unwrap(
        await api.POST("/v1/people/{identity}/assignments/hand-back", {
          params: { path: { identity } },
          body: {},
        }),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["holdings"] });
      // The badge for what nobody holds is counted from the findings list, so
      // that is the key to invalidate. Returning a whole queue is the single
      // act that moves the number most.
      void queries.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="The holdings could not be read." />;
  }
  if (rows.length === 0) {
    return (
      <Empty
        title="Nobody else is holding anything."
        detail="What is waiting for nobody is the findings list under Unassigned; this one is about work somebody has taken on."
      />
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
                          routed to a team is unheld until somebody takes it. */}
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
                  {(row.places ?? 0).toLocaleString()}
                </td>
                <td className="num">
                  {(row.overdue ?? 0) > 0 ? (
                    <span className="due over">{row.overdue}</span>
                  ) : (
                    <span style={{ color: "var(--faint)" }}>0</span>
                  )}
                </td>
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
// built several ways is one piece of work and was taken on as one.
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
  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="The assigned work could not be read." />;
  }
  if (rows.length === 0) return <Empty title={empty} detail={detail} />;

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
              <th className="num">Locations</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={`${row.product} ${row.vulnerability} ${row.component} ${row.version}`}
                className="row"
              >
                <td>
                  <Severity word={row.severity} />
                </td>
                <td>
                  <Link
                    to={pathTo(
                      {
                        product: row.product ?? "",
                        stream: row.stream ?? "",
                        variant: row.variant ?? "",
                      },
                      row,
                    )}
                    className="id"
                  >
                    {row.vulnerability}
                  </Link>{" "}
                  <Exploited when={row.exploited} />
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
                      · {row.stream_name || row.stream} · {row.variant_name || row.variant}
                    </>
                  )}
                </td>
                <td className="num">{row.places}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Wide>
      <Paged shown={rows.length} total={total} offset={offset} limit={PAGE} onGo={onGo} />
    </>
  );
}

// Two letters for the corner. A display name people set is usually a full
// name; an identity is usually not, and either has to fit in a small circle.
