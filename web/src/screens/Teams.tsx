import { useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Suggest } from "../ui/Suggest";
import { matching, offeredAs, whoIs } from "../ui/whom";
import { Wide } from "../ui/Wide";

// Teams: who work arrives for, as a queue rather than as a person.
//
// Teams existed in the API, on the assignments screen as a queue and on the
// auto-assignment screen as a destination, and nowhere anybody could make one
// — so a rule could only route to a team somebody had created with a request
// by hand. That is the gap this closes.
//
// Belonging to a team grants nothing. It says where work arrives and never
// what anybody may read, which is what lets one team carry mixed clearance —
// and it is why this sits beside users and roles rather than inside it.
export function Teams() {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [shown, setShown] = useState("");

  const teams = useQuery({
    queryKey: ["teams"],
    queryFn: async () => unwrap(await api.GET("/v1/teams", {})),
  });
  const people = useQuery({
    queryKey: ["people"],
    queryFn: async () => unwrap(await api.GET("/v1/people", {})),
  });

  const declare = useMutation({
    mutationFn: async (body: { name: string; display_name?: string }) =>
      unwrap(await api.POST("/v1/teams", { body })),
    onSuccess: () => {
      setName("");
      setShown("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["teams"] });
    },
  });
  const retire = useMutation({
    mutationFn: async (team: string) =>
      unwrap(await api.DELETE("/v1/teams/{team}", { params: { path: { team } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["teams"] }),
  });
  const join = useMutation({
    mutationFn: async (who: { team: string; identity: string }) =>
      unwrap(await api.PUT("/v1/teams/{team}/members/{identity}", { params: { path: who } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["teams"] }),
  });
  const leave = useMutation({
    mutationFn: async (who: { team: string; identity: string }) =>
      unwrap(await api.DELETE("/v1/teams/{team}/members/{identity}", { params: { path: who } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["teams"] }),
  });

  if (teams.isPending) return <Loading />;
  if (teams.isError) return <Failed error={teams.error} what="The teams could not be read." />;

  const rows = teams.data?.items ?? [];
  const everybody = (people.data?.items ?? []).map((person) => ({
    identity: person.identity ?? "",
    name: person.display_name || person.identity || "",
  }));

  return (
    <>
      <div className="screen-head">
        <h2>Teams</h2>
        <p>Queues that work is assigned to</p>
        <AddButton label="Add team" onClick={() => setAdding(true)} />
      </div>

      {retire.error != null && (
        <Failed error={retire.error} what="That team could not be retired." />
      )}
      {join.error != null && <Failed error={join.error} what="They could not be added." />}
      {leave.error != null && <Failed error={leave.error} what="They could not be removed." />}

      {rows.length === 0 ? (
        <Empty
          title="No teams are recorded."
          detail="The queues work goes to when it belongs to a group rather than a person."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Team</th>
                <th>Members</th>
                <th style={{ width: 230 }}>Add somebody</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((team) => (
                <tr key={team.name} className="row">
                  <td>
                    <span className="id">{team.display_name || team.name}</span>
                    {team.display_name && team.display_name !== team.name && (
                      <>
                        {" "}
                        <span className="hint">matched as {team.name}</span>
                      </>
                    )}
                  </td>
                  <td>
                    {(team.members ?? []).length === 0 ? (
                      <span style={{ color: "var(--faint)" }}>
                        nobody — work routed here stays unassigned
                      </span>
                    ) : (
                      <span className="variants">
                        {(team.members ?? []).map((who) => (
                          <span key={who} className="vchip">
                            {who}{" "}
                            <button
                              type="button"
                              className="linkish"
                              style={{ fontSize: "inherit" }}
                              title={`Take ${who} off this team`}
                              disabled={leave.isPending}
                              onClick={() => leave.mutate({ team: team.name ?? "", identity: who })}
                            >
                              ×
                            </button>
                          </span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td>
                    <Pick
                      people={everybody.filter(
                        (person) => !(team.members ?? []).includes(person.identity),
                      )}
                      unread={people.isError}
                      busy={join.isPending}
                      onPick={(identity) => join.mutate({ team: team.name ?? "", identity })}
                    />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="linkish"
                      style={{ color: "var(--muted)" }}
                      title="Take it out of use. Work already routed here keeps naming it."
                      disabled={retire.isPending}
                      onClick={() => retire.mutate(team.name ?? "")}
                    >
                      Retire
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <p className="hint" style={{ marginTop: 12 }}>
        Being on a team says where work arrives and never what anybody may read, so one team can
        carry mixed clearance — a member who may not read undisclosed work does not see the
        undisclosed work in its queue. Retiring a team takes it out of use rather than deleting it,
        because work already routed to it has to keep resolving to something a screen can name.{" "}
        <Link to="/auto-assignment" className="linkish">
          Auto-assignment →
        </Link>{" "}
        is where a standing rule hands work to one.
      </p>

      <Declare
        title="Add a team"
        open={adding}
        onClose={() => setAdding(false)}
        busy={declare.isPending}
        error={declare.error}
        ok="Add team"
        hint="Teams hold work. They grant no access."
        onSubmit={() => declare.mutate({ name, ...(shown ? { display_name: shown } : {}) })}
      >
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="platform"
          hint="The name a rule uses for it. Capitals do not matter."
        />
        <Field
          label="Shown as"
          value={shown}
          onChange={setShown}
          placeholder="Platform team"
          hint="Shown on screen. Defaults to the name."
        />
      </Declare>
    </>
  );
}

// Somebody to add, typed against the people already recorded.
//
// A select over everybody the deployment holds is a control that stops working
// at the size a deployment actually reaches: it offers a scroll through
// hundreds of names in no order anybody chose. Typed against the same list, it
// narrows as somebody types and says when nothing matches.
//
// It still cannot invent anybody. Add stays disabled until what is typed
// resolves to one of the people offered, which is the guarantee the select
// gave for free: a team cannot bring anybody into the deployment, and being
// refused after typing is a worse way to learn that than not being offered it.
function Pick({
  people,
  unread,
  busy,
  onPick,
}: {
  people: { identity: string; name: string }[];
  // A readable list of people at all. An empty list and a list
  // nobody could fetch look alike, and only the first of them means the team
  // already holds everybody.
  unread: boolean;
  busy: boolean;
  onPick: (identity: string) => void;
}) {
  const [typed, setTyped] = useState("");
  if (unread) {
    return <span className="hint">who could be added could not be read</span>;
  }
  if (people.length === 0) {
    return <span className="hint">everybody recorded is on it</span>;
  }
  // The whole list is already in the browser, so this is narrowed here rather
  // than asked for again.
  const offered = matching(typed, people).map(offeredAs);
  const who = whoIs(typed, people);
  return (
    <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
      <Suggest
        id="team-add"
        label="Somebody to add"
        value={typed}
        onChange={setTyped}
        options={offered}
        // Opens on focus, because the list is the point: somebody adding to a
        // team is usually looking for a name rather than recalling one.
        from={0}
        placeholder="somebody…"
        disabled={busy}
      />
      <button
        type="button"
        className="btn quiet"
        disabled={busy || who === ""}
        onClick={() => {
          onPick(who);
          setTyped("");
        }}
      >
        Add
      </button>
    </div>
  );
}
