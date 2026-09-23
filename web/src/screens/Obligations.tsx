import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { at, since } from "../ui/when";

// Every standing attack on a product, with the windows this deployment counts
// from the moment each became known and the notices given.
//
// Its own screen rather than a filter over the overdue list: a window here has
// somebody outside waiting on it, and a remediation deadline has nobody. What
// the screen shows is times and parties. Whether a notice met anything is not
// the tool's answer to give, so no row says so.
type Incident = Body<"ObligationBody">;
type Window = Body<"WindowBody">;

export function Obligations() {
  const who = useWho();
  const shelf = useQuery({
    queryKey: ["obligations"],
    queryFn: async () => unwrap(await api.GET("/v1/obligations", {})),
  });
  const windows = useQuery({
    queryKey: ["obligation-windows"],
    queryFn: async () => unwrap(await api.GET("/v1/obligation-windows", {})),
  });

  if (shelf.isPending || windows.isPending) return <Loading />;
  if (shelf.isError) {
    return <Failed error={shelf.error} what="The standing attacks could not be read." />;
  }
  const items = shelf.data?.items ?? [];
  const inForce = windows.data?.items ?? [];

  return (
    <>
      <div className="screen-head">
        <h2>
          Standing attacks <span className="n">{items.length.toLocaleString()}</span>
        </h2>
        <p>
          Products attacked through an issue, and the windows counted from when each became known.
        </p>
      </div>

      {who.data?.admin && <Windows windows={inForce} />}
      {!who.data?.admin && inForce.length === 0 && (
        <p className="hint">No windows are declared. An administrator declares them.</p>
      )}

      {items.length === 0 ? (
        <Empty
          title="No product records being exploited."
          detail="A record kept on a finding appears here until somebody clears it."
        />
      ) : (
        items.map((incident) => (
          <Incident key={incident.id} incident={incident} windows={inForce} />
        ))
      )}
    </>
  );
}

function Incident({ incident, windows }: { incident: Incident; windows: Window[] }) {
  const [telling, setTelling] = useState(false);

  return (
    <div className="card">
      <h3>
        <Link className="id" to={`/issues/${encodeURIComponent(incident.vulnerability ?? "")}`}>
          {incident.vulnerability}
        </Link>{" "}
        in {incident.product_name || incident.product}
        {incident.undisclosed && <span className="hint"> · undisclosed</span>}
      </h3>
      <p>
        Known since <b style={{ color: "var(--ink)" }}>{at(incident.known_at)}</b>
        {incident.recorded_by && <> · recorded by {incident.recorded_by}</>}
      </p>
      <p>{incident.grounds}</p>

      {(incident.windows ?? []).length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Window</th>
              <th>Ends</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(incident.windows ?? []).map((due) => (
              <tr key={due.window.id}>
                <td>{due.window.name}</td>
                <td title={at(due.ends_at)}>
                  <span className={due.answered ? "" : due.passed ? "due over" : "due soon"}>
                    {at(due.ends_at)}
                  </span>
                </td>
                <td className="hint">
                  {due.answered
                    ? "notice recorded"
                    : due.passed
                      ? since(due.ends_at)
                      : `${due.near ? "ending soon · " : ""}ends ${since(due.ends_at)}`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {(incident.told ?? []).length > 0 && (
        <>
          <h3 style={{ marginTop: 12 }}>Told</h3>
          {(incident.told ?? []).map((one) => (
            <p key={one.id}>
              <b style={{ color: "var(--ink)" }}>{one.recipient}</b> at {at(one.told_at)}
              {one.window && (
                <span className="hint">
                  {" "}
                  · for {one.window}
                  {/* A retired window's name may be declared again, so a
                      notice for the old one says which it was. */}
                  {!windows.some((each) => each.id === one.window_id) && " (retired)"}
                </span>
              )}
              <br />
              <span className="hint">{one.said}</span>
            </p>
          ))}
        </>
      )}

      {incident.may_tell &&
        (telling ? (
          <Tell
            id={incident.id ?? 0}
            knownAt={incident.known_at}
            windows={windows}
            onClose={() => setTelling(false)}
          />
        ) : (
          <p>
            <button type="button" className="linkish" onClick={() => setTelling(true)}>
              Record who was told
            </button>
          </p>
        ))}
    </div>
  );
}

function Tell({
  id,
  knownAt,
  windows,
  onClose,
}: {
  id: number;
  knownAt: string;
  windows: Window[];
  onClose: () => void;
}) {
  const queries = useQueryClient();
  // Local wall-clock, which is what the input shows and returns, defaulting to
  // now: most notices are recorded as they are sent.
  const [toldAt, setToldAt] = useState(() => {
    const now = new Date();
    return new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  });
  const [recipient, setRecipient] = useState("");
  const [said, setSaid] = useState("");
  const [answers, setAnswers] = useState("");

  const tell = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/exploited-here/{id}/told", {
          params: { path: { id } },
          body: {
            recipient,
            told_at: new Date(toldAt).toISOString(),
            said,
            ...(answers ? { window: Number(answers) } : {}),
          },
        }),
      ),
    onSuccess: () => {
      onClose();
      void queries.invalidateQueries({ queryKey: ["obligations"] });
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  return (
    <div className="rating">
      {tell.error != null && <Failed error={tell.error} what="That notice was not recorded." />}
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="recipient">Who</label>
        <input
          id="recipient"
          type="text"
          value={recipient}
          placeholder="A regulator, a customer, a response team"
          onChange={(event) => setRecipient(event.target.value)}
        />
      </div>
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="toldat">When</label>
        <input
          id="toldat"
          type="datetime-local"
          style={{ width: "auto" }}
          value={toldAt}
          title={`Not before ${at(knownAt)}`}
          onChange={(event) => setToldAt(event.target.value)}
        />
      </div>
      {windows.length > 0 && (
        <div className="field" style={{ marginBottom: 8 }}>
          <label htmlFor="answers">For</label>
          <select id="answers" value={answers} onChange={(event) => setAnswers(event.target.value)}>
            <option value="">No window</option>
            {windows.map((each) => (
              <option key={each.id} value={each.id}>
                {each.name}
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="said">What they were told</label>
        <textarea
          id="said"
          style={{ minHeight: 64 }}
          value={said}
          onChange={(event) => setSaid(event.target.value)}
        />
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={!recipient.trim() || !said.trim() || !toldAt || tell.isPending}
          onClick={() => tell.mutate()}
        >
          Record
        </button>
        <button type="button" className="btn quiet" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

// The windows this deployment counts, for an administrator to declare, change
// and retire. None ships.
function Windows({ windows }: { windows: Window[] }) {
  const queries = useQueryClient();
  const [editing, setEditing] = useState<number | null>(null);
  const done = () => {
    setEditing(null);
    void queries.invalidateQueries({ queryKey: ["obligation-windows"] });
    void queries.invalidateQueries({ queryKey: ["obligations"] });
  };
  const retire = useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.DELETE("/v1/obligation-windows/{id}", { params: { path: { id } } })),
    onSuccess: done,
  });

  return (
    <div className="card">
      <h3>Windows</h3>
      {windows.length === 0 && <p className="hint">None declared.</p>}
      {windows.map((each) =>
        editing === each.id ? (
          <WindowForm key={each.id} window={each} onDone={done} onCancel={() => setEditing(null)} />
        ) : (
          <p key={each.id}>
            {each.name}{" "}
            <span className="hint">
              · {each.hours} hours
              {each.lead_hours ? ` · warned ${each.lead_hours} hours before` : ""}
              {" · "}
              {(each.products ?? []).length > 0
                ? (each.products ?? []).join(", ")
                : "every product"}
            </span>{" "}
            <button type="button" className="linkish" onClick={() => setEditing(each.id)}>
              Edit
            </button>{" "}
            <button
              type="button"
              className="linkish"
              disabled={retire.isPending}
              onClick={() => retire.mutate(each.id)}
            >
              Retire
            </button>
          </p>
        ),
      )}
      {retire.error != null && <Failed error={retire.error} what="That window was not retired." />}
      {editing === null && <WindowForm onDone={done} />}
    </div>
  );
}

// WindowForm declares a window, or restates one when it is handed it. Every
// field is sent, because a change replaces what the window says.
function WindowForm({
  window,
  onDone,
  onCancel,
}: {
  window?: Window;
  onDone: () => void;
  onCancel?: () => void;
}) {
  const [name, setName] = useState(window?.name ?? "");
  const [hours, setHours] = useState(window ? String(window.hours) : "");
  const [lead, setLead] = useState(window?.lead_hours ? String(window.lead_hours) : "");
  const [limited, setLimited] = useState<string[]>(window?.products ?? []);
  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });

  const body = () => ({
    name,
    hours: Number(hours),
    ...(Number(lead) > 0 ? { lead_hours: Number(lead) } : {}),
    ...(limited.length > 0 ? { products: limited } : {}),
  });
  const save = useMutation({
    mutationFn: async () =>
      window
        ? unwrap(
            await api.PUT("/v1/obligation-windows/{id}", {
              params: { path: { id: window.id } },
              body: body(),
            }),
          )
        : unwrap(await api.POST("/v1/obligation-windows", { body: body() })),
    onSuccess: () => {
      if (!window) {
        setName("");
        setHours("");
        setLead("");
        setLimited([]);
      }
      onDone();
    },
  });
  const toggle = (product: string) =>
    setLimited((was) =>
      was.includes(product) ? was.filter((each) => each !== product) : [...was, product],
    );

  return (
    <div style={{ marginTop: 8 }}>
      <div className="actions">
        <input
          type="text"
          aria-label="Name"
          style={{ width: "32ch" }}
          placeholder="Name"
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
        <input
          aria-label="Hours"
          type="number"
          min={1}
          placeholder="Hours"
          style={{ width: "10ch" }}
          value={hours}
          onChange={(event) => setHours(event.target.value)}
        />
        <input
          aria-label="Warn this many hours before the end"
          title="A second notice this many hours before the end. Leave empty for none"
          type="number"
          min={1}
          placeholder="Warn at"
          style={{ width: "10ch" }}
          value={lead}
          onChange={(event) => setLead(event.target.value)}
        />
      </div>
      {(products.data?.items ?? []).length > 0 && (
        <p className="hint" title="None ticked is every product">
          Applies to{" "}
          {(products.data?.items ?? []).map((product) => (
            <label key={product.name} style={{ marginLeft: 8, marginRight: 4 }}>
              <input
                type="checkbox"
                checked={limited.includes(product.name)}
                onChange={() => toggle(product.name)}
              />{" "}
              {product.display_name || product.name}
            </label>
          ))}
          {limited.length === 0 && "· every product"}
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={!name.trim() || !(Number(hours) > 0) || save.isPending}
          onClick={() => save.mutate()}
        >
          {window ? "Save" : "Declare"}
        </button>
        {onCancel && (
          <button type="button" className="btn quiet" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
      {save.error != null && (
        <Failed
          error={save.error}
          what={window ? "That window was not changed." : "That window was not declared."}
        />
      )}
    </div>
  );
}
