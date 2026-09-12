import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Empty } from "../ui/Empty";
import { called } from "../ui/roles";

// One person, whole.
//
// Four questions that were answerable only by reading four screens against
// each other, and two of them could not be asked at all: what somebody was
// told while holding a role that has since been withdrawn, and how much of the
// record rests on this one person.
//
// **What they were told is not narrowed by what they may read now.** That is
// the point of asking: a line about an undisclosed finding, sent while they
// held the role that reached it, is exactly what an investigation is looking
// for. The area they read themselves is narrowed; this is a different question
// asked by somebody who administers the deployment.
export function Person() {
  const { identity = "" } = useParams();
  const queries = useQueryClient();
  const about = useQuery({
    queryKey: ["person", identity],
    queryFn: async () =>
      unwrap(await api.GET("/v1/people/{identity}", { params: { path: { identity } } })),
  });

  // Leaving and coming back are two verbs on one thing rather than two verbs
  // on the person: nobody is created or destroyed here.
  const leaving = useMutation({
    mutationFn: async (gone: boolean) =>
      unwrap(
        gone
          ? await api.PUT("/v1/people/{identity}/deactivation", { params: { path: { identity } } })
          : await api.DELETE("/v1/people/{identity}/deactivation", {
              params: { path: { identity } },
            }),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["person", identity] });
      void queries.invalidateQueries({ queryKey: ["people"] });
    },
  });

  if (about.isPending) return <Loading />;
  if (about.isError) {
    return <Failed error={about.error} what="This person could not be read." />;
  }
  const who = about.data;
  const record = who.record;

  return (
    <>
      <div className="screen-head">
        <h2>{who.display_name || who.identity}</h2>
        <p>
          <span className="id">{who.identity}</span>
          {who.admin && <> · administers this deployment</>} · <Link to="/people">All users</Link>
        </p>
      </div>

      {/* Said at the top rather than in a panel below: every other number on
          this screen reads differently once somebody has gone. */}
      {who.deactivated_at && (
        <section className="panel" style={{ marginBottom: 14 }}>
          <h3>They have left</h3>
          <p className="hint" style={{ marginTop: 0 }}>
            Recorded on {stamp(who.deactivated_at)}. They are refused at every way in and what they
            were dealing with was handed back. Nothing was deleted: they are still named by every
            judgment they proposed and every one they agreed to, and the roles below are still
            theirs, so bringing them back does not mean granting again.
          </p>
          <button type="button" onClick={() => leaving.mutate(false)} disabled={leaving.isPending}>
            Bring them back
          </button>
        </section>
      )}

      <section className="panel">
        <h3>What they hold</h3>
        {/* "In force" is about the grant, not about them. Sitting under "they
            have left" it reads as a contradiction unless it says which. */}
        {who.deactivated_at && (
          <p className="hint" style={{ marginTop: 0 }}>
            In force means the grant still stands, not that they can use it: they are refused before
            any of this is read.
          </p>
        )}
        {who.holds?.length ? (
          <>
            {/* A role that grants nothing reads very differently from holding
                none at all, and the list alone cannot say which. */}
            {who.sees_nothing && (
              <p className="hint" style={{ marginTop: 0 }}>
                Every role here is a capability, and a capability is bounded by what its holder may
                read — so none of them reaches a product and they see nothing. Holding roles that
                grant nothing is not the same as holding none.
              </p>
            )}
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>Product</th>
                    <th>Role</th>
                    <th>In force</th>
                    <th>Where it came from</th>
                  </tr>
                </thead>
                <tbody>
                  {who.holds.map((held, at) => (
                    <tr key={`${held.product} ${held.role} ${at}`}>
                      <td className="id">{held.product}</td>
                      <td>{called(held.role)}</td>
                      <td>{held.effective ? "Yes" : <span className="hint">No</span>}</td>
                      <td className="hint">{held.source || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <Empty
            title="Nothing"
            detail="They hold no role on any product, so they can sign in and read nothing."
          />
        )}
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Their part in the record</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          An agreement taken back is counted apart from one that stands: it is not somebody who
          agrees.
        </p>
        <ul className="files catalog">
          <li>
            <div>
              <b>{record.proposed.toLocaleString()}</b> claims argued
            </div>
            <div className="hint">
              {record.last_proposed_at ? `Last on ${stamp(record.last_proposed_at)}` : "Never"}
            </div>
          </li>
          <li>
            <div>
              <b>{record.approved.toLocaleString()}</b> claims agreed to, still standing
            </div>
            <div className="hint">
              {record.last_approved_at ? `Last on ${stamp(record.last_approved_at)}` : "Never"}
            </div>
          </li>
          <li>
            <div>
              <b>{record.withdrawn.toLocaleString()}</b> agreements taken back
            </div>
            <div className="hint">
              Counted apart. What the rubber-stamp report asks across a program, asked about one
              person.
            </div>
          </li>
        </ul>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Roles granted and withdrawn</h3>
        {who.held?.length ? (
          <>
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>What</th>
                    <th>Before</th>
                    <th>After</th>
                    <th>By</th>
                  </tr>
                </thead>
                <tbody>
                  {who.held.map((change, at) => (
                    <tr key={`${change.at} ${change.about} ${at}`}>
                      <td className="hint">{stamp(change.at)}</td>
                      <td className="id">{change.about}</td>
                      {/* Absent before means nobody had set it; absent after
                          means it was withdrawn. Two different acts, and a
                          blank cannot tell them apart. */}
                      <td>
                        {change.was ? called(change.was) : <span className="hint">nothing</span>}
                      </td>
                      <td>
                        {change.now ? called(change.now) : <span className="hint">withdrawn</span>}
                      </td>
                      <td className="id">{change.by}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {who.held_total > who.held.length && (
              <p className="hint" style={{ marginTop: 6 }}>
                The most recent {who.held.length} of {who.held_total.toLocaleString()}.
              </p>
            )}
          </>
        ) : (
          <Empty
            title="Nothing recorded"
            detail="No role has been granted to or withdrawn from them since this deployment began keeping the record."
          />
        )}
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>What they were told</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Everything sent to them, including what they have acknowledged and what has since cleared:
          the question is what was sent, not what is waiting. Not narrowed by what they may read now
          — a line about an undisclosed finding, sent while they held the role that reached it, is
          what this is for.
        </p>
        {who.told?.length ? (
          <>
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>What</th>
                    <th>Said</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {who.told.map((told, at) => (
                    <tr key={`${told.at} ${told.kind} ${at}`}>
                      <td className="hint">{stamp(told.at)}</td>
                      <td className="id">
                        {told.kind}
                        {told.private && <span className="hint"> · undisclosed</span>}
                      </td>
                      <td>{told.link ? <Link to={told.link}>{told.body}</Link> : told.body}</td>
                      <td className="hint">
                        {told.cleared ? "cleared" : told.read ? "read" : "unread"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {who.told_total > who.told.length && (
              <p className="hint" style={{ marginTop: 6 }}>
                The most recent {who.told.length} of {who.told_total.toLocaleString()}.
              </p>
            )}
          </>
        ) : (
          <Empty title="Nothing" detail="This deployment has never told them anything." />
        )}
      </section>

      {!who.deactivated_at && (
        <section className="panel" style={{ marginTop: 14 }}>
          <h3>When they leave</h3>
          <p className="hint" style={{ marginTop: 0 }}>
            An identity provider never tells us an account was disabled, and somebody who has left
            never signs in again — so nothing detects it, and the account stays live holding
            whatever it held. Recording it here refuses them at every way in from the next request
            onward, ends their sessions, and hands back what they were dealing with.
          </p>
          <p className="hint">
            Not a deletion, and their roles are left alone: what somebody held is part of why the
            record reads as it does, so bringing them back does not mean granting again.
          </p>
          {leaving.isError && <p className="hint">That could not be recorded. Nothing changed.</p>}
          <button type="button" onClick={() => leaving.mutate(true)} disabled={leaving.isPending}>
            Record that they have left
          </button>
        </section>
      )}
    </>
  );
}

// The same shape the record's own trail table uses: the day and the minute,
// which is the resolution somebody correlating a grant with a message needs,
// and no more.
function stamp(at?: string): string {
  return (at ?? "").slice(0, 16).replace("T", " ");
}
