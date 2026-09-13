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

// The most the server returns of what is running out. A cap rather than a
// page — the list has no total — so a full list is said to be a cap and not
// a count.
const PAGE = 50;

// Assignments: what is running out of time undecided, and what each person
// holds. Unassigned already has its own entry in the rail, so the third tab
// links across rather than drawing the list twice.
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
  const holdings = useQuery({
    queryKey: ["holdings"],
    queryFn: async () => unwrap(await api.GET("/v1/assignments", {})),
  });
  // Whose work is being looked at on the second tab. Empty is the roll-up of
  // everybody; a name is that person's list.
  const person = params.get("person") ?? "";
  const mine = useQuery({
    queryKey: ["assigned", "me", scope],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people/{identity}/assignments", {
          params: { path: { identity: "me" }, query: { limit: PAGE, ...scope } },
        }),
      ),
  });
  const theirs = useQuery({
    enabled: person !== "",
    queryKey: ["assigned", person, scope],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people/{identity}/assignments", {
          params: { path: { identity: person }, query: { limit: PAGE, ...scope } },
        }),
      ),
  });

  function go(next: string) {
    const now = new URLSearchParams(params);
    if (next === "due") now.delete("tab");
    else now.set("tab", next);
    setParams(now);
  }

  const peopleRows = holdings.data?.items ?? [];
  // Nobody's work appears on this screen. What is waiting for nobody is its
  // own screen and its own question — mixing it in here made "assignments" a
  // list of things that are not assigned, which is the one thing it should
  // not be.
  const others = peopleRows.filter((row) => row.person !== who.data?.identity);
  const myCount = peopleRows.find((row) => row.person === who.data?.identity)?.open ?? 0;

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

      {tab === "due" ? (
        <Held
          rows={mine.data?.items ?? []}
          total={mine.data?.total ?? 0}
          query={mine}
          empty="Nothing is assigned to you."
          detail="Work you take on from a finding, or that somebody hands you, appears here."
        />
      ) : person ? (
        <>
          <div className="filters" style={{ marginBottom: 10 }}>
            <button
              type="button"
              className="linkish"
              onClick={() => {
                const now = new URLSearchParams(params);
                now.delete("person");
                setParams(now);
              }}
            >
              ← Everybody
            </button>
            <span className="hint">
              What <b>{person}</b> is dealing with
            </span>
          </div>
          <Held
            rows={theirs.data?.items ?? []}
            total={theirs.data?.total ?? 0}
            query={theirs}
            empty="They are not holding anything."
            detail="Either it has been decided, or somebody handed it back."
          />
        </>
      ) : (
        <ByPerson
          rows={others}
          query={holdings}
          onPick={(identity) => {
            const now = new URLSearchParams(params);
            now.set("person", identity);
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
  rows: { person?: string; team?: boolean; open?: number; places?: number; overdue?: number }[];
  query: Query;
  onPick: (identity: string) => void;
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
      void queries.invalidateQueries({ queryKey: ["unassigned"] });
    },
  });

  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="What people are holding could not be read." />;
  }
  if (rows.length === 0) {
    return (
      <Empty
        title="Nobody else is holding anything."
        detail="What is waiting for nobody is on the unassigned screen; this one is about work somebody has taken on."
      />
    );
  }

  return (
    <>
      {release.error != null && (
        <Failed error={release.error} what="Their work could not be released." />
      )}
      <div className="tablewrap">
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
              <tr key={row.person} className="row">
                <td>
                  <button
                    type="button"
                    className="linkish"
                    onClick={() => onPick(row.person ?? "")}
                    title="See what they are dealing with"
                  >
                    <span className="who2">
                      {/* A team is a queue rather than a person, and drawing
                          it with somebody's initials says the opposite: work
                          routed to a team is unheld until somebody takes it. */}
                      <span className="avatar">{row.team ? "◇" : initials(row.person ?? "")}</span>
                      {row.person}
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
                  <button
                    type="button"
                    className="btn quiet"
                    title={
                      row.team
                        ? "Empty this queue back into the unassigned list"
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
      </div>
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

// What one person is dealing with, in the same units as what nobody is: one
// row per issue in a component in a product, not one per build. The same code
// built several ways is one piece of work and was taken on as one.
function Held({
  rows,
  total,
  query,
  empty,
  detail,
}: {
  rows: Body<"UnassignedBody">[];
  total: number;
  query: Query;
  empty: string;
  detail: string;
}) {
  if (query.isPending) return <Loading />;
  if (query.isError) {
    return <Failed error={query.error} what="What is assigned could not be read." />;
  }
  if (rows.length === 0) return <Empty title={empty} detail={detail} />;

  return (
    <>
      <div className="tablewrap">
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
                    to={
                      `/products/${encodeURIComponent(row.product ?? "")}` +
                      `/streams/${encodeURIComponent(row.stream ?? "")}` +
                      `/variants/${encodeURIComponent(row.variant ?? "")}` +
                      `/findings/${encodeURIComponent(row.vulnerability ?? "")}` +
                      `/components/${encodeURIComponent(row.component ?? "")}` +
                      (row.version ? `?version=${encodeURIComponent(row.version)}` : "")
                    }
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
                  {row.product}
                  {(row.builds ?? 1) > 1 ? (
                    <> · {row.builds} builds</>
                  ) : (
                    <>
                      {" "}
                      · {row.stream} · {row.variant}
                    </>
                  )}
                </td>
                <td className="num">{row.places}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="filters" style={{ margin: "10px 0 0" }}>
        <span className="hint">
          Showing {rows.length.toLocaleString()} of {total.toLocaleString()}
        </span>
      </div>
    </>
  );
}

// Two letters for the corner. A display name people set is usually a full
// name; an identity is usually not, and either has to fit in a small circle.
