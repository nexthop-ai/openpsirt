import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Wide } from "../ui/Wide";
import { since } from "../ui/when";

// What the deployment itself is doing, rather than what it has found.
//
// **Three things were built and reachable from nothing.** Work the queue gave
// up on had an endpoint and a retry route and no screen; what is waiting and
// the bound that refuses more of it were settable and shown nowhere; and where
// this deployment sends what it has to say was configurable only by calling
// the API by hand.
//
// An operator's screen rather than an auditor's, which is not where it
// started: what a worker reported can quote what the job was about, and a
// destination's address is the credential for two of the services it names.
// Neither is one of the deployment's own records.
//
// They are one screen because they are one question — is this deployment
// working — and because each of them fails silently. A queue that has given up
// looks exactly like a quiet one, and a destination that has been refusing for
// a week looks exactly like a destination nothing has been sent to.
export function System() {
  return (
    <>
      <div className="screen-head">
        <h2>System</h2>
        <p>What this deployment is doing, and where it sends what it has to say</p>
      </div>
      <TheQueue />
      <Destinations />
    </>
  );
}

// What is waiting, and what stopped being retried.
function TheQueue() {
  const queries = useQueryClient();
  const work = useQuery({
    queryKey: ["set-aside"],
    queryFn: async () => unwrap(await api.GET("/v1/work/set-aside", {})),
  });
  const retry = useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.POST("/v1/work/set-aside/{id}/retry", { params: { path: { id } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["set-aside"] }),
  });

  if (work.isPending) return <Loading />;
  if (work.isError) {
    return <Failed error={work.error} what="What the queue is doing could not be read." />;
  }
  const waiting = work.data?.waiting ?? [];
  const rows = work.data?.items ?? [];

  return (
    <>
      <section className="panel">
        <h3>Waiting</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Per kind, against the bound that refuses more. Work held by a worker that has stopped
          reporting counts as waiting.
        </p>
        {waiting.length === 0 ? (
          <Empty title="There is no queue here." detail="This process runs no background work." />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Waiting</th>
                <th>Refused past</th>
              </tr>
            </thead>
            <tbody>
              {waiting.map((kind) => (
                <tr key={kind.kind}>
                  <td className="id">{kind.kind}</td>
                  <td>
                    {(kind.waiting ?? 0).toLocaleString()}
                    {(kind.waiting ?? 0) >= (kind.limit ?? 0) && (
                      <>
                        {" "}
                        <span className="state closed">at the bound</span>
                      </>
                    )}
                  </td>
                  <td className="hint">{(kind.limit ?? 0).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h3>Given up on</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Tried as many times as it is allowed to be. Nothing picks it up again until somebody puts
          it back.
        </p>
        {retry.error != null && (
          <Failed error={retry.error} what="That job could not be put back." />
        )}
        {rows.length === 0 ? (
          <Empty
            title="Nothing has been given up on."
            detail="Every job either finished or is still being tried."
          />
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>About</th>
                  <th>Tried</th>
                  <th>Stopped</th>
                  <th>Why</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((job) => (
                  <tr key={job.id} className="row">
                    <td className="id">{job.kind}</td>
                    {/* The queue's own words. What it points at may have been
                        deleted since, and a list that fails to render because
                        one row points at nothing is worse than one that says
                        what the row says. */}
                    <td className="id">{job.reference}</td>
                    <td>{job.attempts}</td>
                    <td className="hint" title={job.stopped_at}>
                      {since(job.stopped_at)}
                    </td>
                    <td className="hint">
                      {job.last_error || (
                        <span style={{ color: "var(--faint)" }}>nothing said</span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="linkish"
                        disabled={retry.isPending}
                        onClick={() => retry.mutate(job.id ?? 0)}
                      >
                        Put back
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        )}
        {(work.data?.total ?? 0) > rows.length && (
          <p className="hint">
            Showing {rows.length.toLocaleString()} of {(work.data?.total ?? 0).toLocaleString()}.
          </p>
        )}
      </section>
    </>
  );
}

// Where this deployment sends what it has to say.
//
// One signed request rather than an adapter each: Slack, Teams, a tracker
// driven by automation and paging all take an HTTP request with a JSON body.
// The secret is never returned by anything, so changing one means recording
// the destination again.
function Destinations() {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("*");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");

  const sent = useQuery({
    queryKey: ["outbound"],
    queryFn: async () => unwrap(await api.GET("/v1/outbound", {})),
  });
  const add = useMutation({
    mutationFn: async (body: { name: string; kind: string; url: string; secret: string }) =>
      unwrap(await api.POST("/v1/outbound", { body })),
    onSuccess: () => {
      setName("");
      setKind("*");
      setUrl("");
      setSecret("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["outbound"] });
    },
  });
  const retire = useMutation({
    mutationFn: async (where: { name: string; kind: string }) =>
      unwrap(await api.DELETE("/v1/outbound/{name}/{kind}", { params: { path: where } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["outbound"] }),
  });

  const rows = sent.data?.items ?? [];

  return (
    <section className="panel">
      <div className="screen-head">
        <h3>Where things are sent</h3>
        <AddButton label="Add destination" onClick={() => setAdding(true)} />
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        Every request is signed: a timestamp, and an HMAC over it and the body.
      </p>
      {retire.error != null && (
        <Failed error={retire.error} what="That destination could not be retired." />
      )}
      {sent.isPending ? (
        <Loading />
      ) : sent.isError ? (
        <Failed error={sent.error} what="Where things are sent could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title="Nothing is sent anywhere."
          detail="Notifications stay inside the application, and mail goes where an address is recorded."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Where</th>
                <th>Sent</th>
                <th>Failing</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.name} ${row.kind}`} className="row">
                  <td className="id">{row.name}</td>
                  <td>{row.kind === "*" ? "everything" : row.kind}</td>
                  {/* The address as recorded. It is not a link: it is
                      somewhere this deployment posts to, not somewhere a
                      person goes, and for two of the services it names the
                      path is the credential. */}
                  <td className="id">{row.url}</td>
                  <td>{(row.sent ?? 0).toLocaleString()}</td>
                  <td>
                    {(row.failing ?? 0) === 0 ? (
                      <span style={{ color: "var(--faint)" }}>none</span>
                    ) : (
                      <span className="state closed" title={row.because}>
                        {(row.failing ?? 0).toLocaleString()}
                      </span>
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="linkish"
                      disabled={retire.isPending}
                      onClick={() => retire.mutate({ name: row.name ?? "", kind: row.kind ?? "" })}
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

      <Declare
        title="Add destination"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() =>
          add.mutate({
            name: name.trim(),
            kind: kind.trim() || "*",
            url: url.trim(),
            secret: secret.trim(),
          })
        }
        error={add.error}
        busy={name.trim() === "" || url.trim() === "" || secret.trim().length < 16 || add.isPending}
        ok="Add destination"
        hint="https only. A redirect is refused rather than followed: the body is signed and not encrypted."
      >
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="security-channel"
          hint="What a log line and this screen call it."
        />
        <Field
          label="Kind"
          value={kind}
          onChange={setKind}
          placeholder="*"
          hint="One notification kind, or * for all of them."
        />
        <Field
          label="URL"
          value={url}
          onChange={setUrl}
          placeholder="https://hooks.example.com/services/…"
        />
        <Field
          label="Signing secret"
          value={secret}
          onChange={setSecret}
          hint="At least 16 characters. It signs our requests rather than authenticating anybody to us, and no endpoint ever returns it."
        />
      </Declare>
    </section>
  );
}
