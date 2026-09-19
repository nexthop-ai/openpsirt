import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Wide } from "../ui/Wide";
import { since } from "../ui/when";
import { WebhookDelivery } from "./Webhooks";

// The deployment's own state, rather than what it has found.
//
// Three things were built and reachable from nothing. Work the queue gave
// up on had an endpoint and a retry route and no screen; what is waiting and
// the bound that refuses more of it were settable and shown nowhere; and where
// this deployment sends what it has to say was configurable only by calling
// the API by hand.
//
// An operator's screen rather than an auditor's, which is not where it
// started: what a worker reported can quote what the job was about. That is
// not one of the deployment's own records.
//
// They are one screen because they are one question — is this deployment
// working — and because each of them fails silently. A queue that has given up
// looks exactly like a quiet one, and a webhook that has been refusing for a
// week looks exactly like one nothing has been sent to.
//
// Configuring a webhook is not here. Adding one is administration and sits
// under Settings with the rest of what a deployment is set to; what is here is
// whether the ones configured are arriving. The address is the credential, so
// it stays on the screen that configures them.
export function System() {
  return (
    <>
      <div className="screen-head">
        <h2>System</h2>
        <p>What this deployment is doing, and whether what it posts is arriving</p>
      </div>
      <VulnerabilityData />
      <TheQueue />
      <WhatUpstreamCouldNotAnswer />
      <WebhookDelivery />
    </>
  );
}

// The rows drawn. Past this it is a list nobody reads through, and the
// count beside it says how much there is.
const MOST = 100;

// The components public indexes could not answer for, and the reason for each.
//
// Two questions that are one panel. What was held back says what the
// derived default is costing; what no index has heard of is the list an
// operator reads to decide what else should be held back. A name promoted from
// the second appears in the first afterwards, which is how somebody knows the
// promotion worked.
//
// Nothing here is a fault, which is why the empty state is the good news and
// the table is not drawn in a failing color. A private module, a vendored
// fork and a name this deployment publishes under all reach it.
function WhatUpstreamCouldNotAnswer() {
  const asked = useQuery({
    queryKey: ["upstream-unanswered"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/upstream/unanswered", { params: { query: { limit: MOST } } })),
  });

  if (asked.isPending) return <Loading />;
  if (asked.isError) {
    return <Failed error={asked.error} what="The components upstream could not answer for could not be read." />;
  }
  const rows = asked.data?.items ?? [];
  const total = asked.data?.total ?? 0;
  // Drawn whatever the table holds. A derived default nobody can see is one an
  // operator turns the whole feature off to escape, and this is not a
  // statement about any product, so it does not narrow with the rows.
  const ours = asked.data?.ours ?? [];

  return (
    <section className="panel">
      <h3>Upstream</h3>
      <p
        className="hint"
        style={{ marginTop: 0 }}
        title="Asking a public package index sends the component's name. A name matching one of these is never sent."
      >
        Held back:{" "}
        {ours.length === 0 ? (
          <span>nothing</span>
        ) : (
          ours.map((name) => (
            <span key={name} className="id" style={{ marginRight: "0.75ch" }}>
              {name}
            </span>
          ))
        )}
      </p>
      {rows.length === 0 ? (
        <Empty
          title="Nothing here has gone unanswered."
          detail="Only components in products you may read are counted, and only after the pass has reached them — a deployment that has not turned asking on has reached none of them yet."
        />
      ) : (
        <>
          <p className="hint">
            {total.toLocaleString()} without an answer
            {rows.length < total && `, ${rows.length.toLocaleString()} shown`}. Only components in
            products you may read.{" "}
            {asked.data?.whole === false &&
              "This estate is past what one read examines, so the count is a floor."}
          </p>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Ecosystem</th>
                  <th>Why</th>
                  <th>Last reached</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.purl} className="row">
                    <td className="id">{row.purl}</td>
                    <td className="hint">{row.ecosystem || "—"}</td>
                    <td>{because(row.why)}</td>
                    <td className="hint">{since(row.checked)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        </>
      )}
    </section>
  );
}

// The vulnerability data the scans answer against, and when it last moved.
//
// The half of "the fact and a link" that did not work. Somebody told the
// vulnerability data has stopped moving arrived at this screen, which showed
// the job queue and the webhooks and nothing about the data at all. The
// version was in the database and on no screen anywhere.
//
// It fails silently like everything else here, which is why it belongs on this
// screen rather than beside a build: every scan since the data stopped goes on
// answering as confidently as ever, and nothing reports a fault.
function VulnerabilityData() {
  const data = useQuery({
    queryKey: ["vulnerability-data"],
    queryFn: async () => unwrap(await api.GET("/v1/vulnerability-data", {})),
  });

  if (data.isPending) return <Loading />;
  if (data.isError) {
    return (
      <Failed error={data.error} what="The vulnerability data the scans answer against could not be read." />
    );
  }
  const version = data.data?.version ?? "";
  const moved = data.data?.moved_at;

  return (
    <section className="panel">
      <h3>Vulnerability data</h3>
      <p className="hint" style={{ marginTop: 0 }}>
        What every scan is answering against. The version is the scanner&rsquo;s own spelling and
        nothing orders it — what matters is that it moves, not which is newer.
      </p>
      {version === "" ? (
        <Empty
          title="No scan has finished and stated a version."
          detail="Nothing has been pointed at this deployment yet, which is a different thing from data that has stopped moving."
        />
      ) : (
        <table>
          <tbody>
            <tr>
              <th scope="row">In force</th>
              <td className="id">{version}</td>
            </tr>
            <tr>
              <th scope="row">Last moved</th>
              <td>
                {moved ? since(moved) : <span className="hint">—</span>}
                {data.data?.stale === true && (
                  <>
                    {" "}
                    <span className="state closed">stopped</span>
                  </>
                )}
              </td>
            </tr>
            <tr>
              <th scope="row">Counts as stopped after</th>
              <td className="hint">{data.data?.stale_after}</td>
            </tr>
          </tbody>
        </table>
      )}
    </section>
  );
}

// Each reason's meaning, in words rather than in the vocabulary the API uses.
//
// The three are different things and only one of them is anybody's to act on:
// an unrecognized name is the candidate to hold back, a held-back name is the
// default working, and an unreadable identifier is a document this deployment
// accepted that nothing can turn into a request.
function because(why?: string) {
  switch (why) {
    case "ours":
      return <span className="state closed">held back, ours</span>;
    case "unreadable":
      return <span className="state open">identifier cannot be read</span>;
    default:
      return <span className="hint">no index knows it</span>;
  }
}

// The work waiting, and the work that stopped being retried.
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
    return <Failed error={work.error} what="The queue's own state could not be read." />;
  }
  const waiting = work.data?.waiting ?? [];
  const rows = work.data?.items ?? [];

  return (
    <>
      <section className="panel">
        <h3>Queue</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Per kind, against the limit that refuses more. Work held by a worker that has stopped
          reporting counts as waiting.
        </p>
        {waiting.length === 0 ? (
          <Empty title="Nothing is queued." detail="This process runs no background work." />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Waiting</th>
                <th>Limit</th>
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
                        <span className="state closed">at limit</span>
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
        <h3>Failed jobs</h3>
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
                  <th>Reference</th>
                  <th>Attempts</th>
                  <th>Last attempt</th>
                  <th>Last error</th>
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
