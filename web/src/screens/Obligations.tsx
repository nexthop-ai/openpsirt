// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useDeferredValue, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { AddButton } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { at, since, typedMoment, typedNow } from "../ui/when";
import { issueAt, obligationsAt } from "../app/routes";
import { notACredential } from "../ui/noautofill";
import { Keep } from "./FindingExploited";

// Every standing record that a product was exploited here, with the windows
// this deployment counts for each and the notices given. Called "Exploited
// here" on screen: the words of the record, the finding's badge and the act,
// so the three read as one thing.
//
// Its own screen rather than a filter over the overdue list: a window here has
// somebody outside waiting on it, and a remediation deadline has nobody. What
// the screen shows is times and parties. Whether a notice met anything is not
// the tool's answer to give, so no row says so.
type Incident = Body<"ObligationBody">;
type Window = Body<"WindowBody">;
type Notice = Body<"NoticeBody">;

// What a notice may say about malice, as the form offers it and a notice
// reads back. The server holds the words; these are their labels.
const MALICE: Record<string, string> = {
  yes: "Suspected malicious",
  no: "Not malicious",
  unknown: "Malice unknown",
};

export function Obligations() {
  const who = useWho();
  // A product in the address narrows the shelf to that product's records, so a
  // count taken over one product opens the records it counted. The shelf is
  // unpaged and already narrowed to what the reader may see, so this is a
  // filter over what came back.
  const [params] = useSearchParams();
  const product = params.get("product") ?? "";
  const [recording, setRecording] = useState(false);
  const shelf = useQuery({
    queryKey: ["obligations"],
    queryFn: async () => unwrap(await api.GET("/v1/obligations", {})),
  });
  const windows = useQuery({
    queryKey: ["obligation-windows"],
    queryFn: async () => unwrap(await api.GET("/v1/obligation-windows", {})),
  });

  // Recording asks for triage on the product, so the control is offered to
  // whoever holds it somewhere and the picker offers only those products.
  const triaged = (who.data?.reach ?? []).filter((each) => each.may_triage);

  if (shelf.isPending || windows.isPending) return <Loading />;
  if (shelf.isError) {
    return <Failed error={shelf.error} what="The exploited-here records could not be read." />;
  }
  const items = (shelf.data?.items ?? []).filter(
    (incident) => !product || incident.product === product,
  );
  const productName = items[0]?.product_name || product;
  const inForce = windows.data?.items ?? [];
  // A failed read of the windows is not a deployment with none declared, and
  // a notice for a window nobody could read is not one for a retired window.
  const unread = windows.isError;

  return (
    <>
      <div className="screen-head">
        <h2>
          Exploited here <span className="n">{items.length.toLocaleString()}</span>
        </h2>
        <p>
          {product ? (
            <>
              Exploited here on {productName} · <Link to={obligationsAt()}>every product</Link>
            </>
          ) : (
            "Attacks on our own products, not a feed flag, and the windows counted for each."
          )}
        </p>
        {triaged.length > 0 && (
          <AddButton label="Record exploited here" onClick={() => setRecording((was) => !was)} />
        )}
      </div>

      {recording && <Record products={triaged} onClose={() => setRecording(false)} />}

      {unread && <Failed error={windows.error} what="The windows could not be read." />}
      {!unread && who.data?.admin && <Windows windows={inForce} />}
      {!unread && !who.data?.admin && inForce.length === 0 && (
        <p className="hint">No windows are declared. An administrator declares them.</p>
      )}

      {items.length === 0 ? (
        <Empty
          title={
            product
              ? `${productName} is not recorded as exploited.`
              : "No products recorded as exploited."
          }
          detail={
            triaged.length > 0
              ? "Use Record exploited here, above or on the finding. A record stays until cleared."
              : "Somebody who triages the product records one on its finding."
          }
        />
      ) : (
        items.map((incident) => (
          <Incident key={incident.id} incident={incident} windows={inForce} known={!unread} />
        ))
      )}
    </>
  );
}

function Incident({
  incident,
  windows,
  known,
}: {
  incident: Incident;
  windows: Window[];
  known: boolean;
}) {
  const [telling, setTelling] = useState(false);

  return (
    <div className="card">
      <h3>
        <Link className="id" to={issueAt(incident.vulnerability ?? "")}>
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
                {due.started ? (
                  <td title={`From ${at(due.starts_at)}`}>
                    <span className={due.answered ? "" : due.passed ? "due over" : "due soon"}>
                      {at(due.ends_at)}
                    </span>
                  </td>
                ) : (
                  <td className="hint">Not started</td>
                )}
                <td className="hint">
                  {due.answered
                    ? "notice recorded"
                    : !due.started
                      ? `starts at the first notice for ${due.window.from_name ?? "another window"}`
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
                  {known && !windows.some((each) => each.id === one.window_id) && " (retired)"}
                </span>
              )}
              <Particulars notice={one} />
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

// What a notice carried beyond who, when and what, where it carried any.
function Particulars({ notice }: { notice: Notice }) {
  const parts = [
    notice.reference,
    (notice.places ?? []).join(", "),
    notice.suspected_malicious ? MALICE[notice.suspected_malicious] : "",
  ].filter((part) => part);
  if (parts.length === 0) return null;
  return <span className="hint"> · {parts.join(" · ")}</span>;
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
  // Typed in UTC, as the card draws every moment, and defaulting to now: most
  // notices are recorded as they are sent.
  const [toldAt, setToldAt] = useState(() => typedNow());
  const [recipient, setRecipient] = useState("");
  const [said, setSaid] = useState("");
  const [answers, setAnswers] = useState("");
  const [reference, setReference] = useState("");
  const [places, setPlaces] = useState("");
  const [malice, setMalice] = useState("");
  const named = places
    .split(/[,\n]/)
    .map((place) => place.trim())
    .filter((place) => place);

  const tell = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/exploited-here/{id}/told", {
          params: { path: { id } },
          body: {
            recipient,
            told_at: typedMoment(toldAt),
            said,
            ...(answers ? { window: Number(answers) } : {}),
            ...(reference.trim() ? { reference: reference.trim() } : {}),
            ...(named.length > 0 ? { places: named } : {}),
            ...(malice ? { suspected_malicious: malice as "yes" | "no" | "unknown" } : {}),
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
        <label htmlFor="recipient">Recipient</label>
        <input
          id="recipient"
          type="text"
          value={recipient}
          placeholder="A regulator, a customer, a response team"
          onChange={(event) => setRecipient(event.target.value)}
        />
      </div>
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="toldat">Told at (UTC)</label>
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
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="reference">Reference</label>
        <input
          id="reference"
          type="text"
          value={reference}
          placeholder="Their case or submission number"
          onChange={(event) => setReference(event.target.value)}
        />
      </div>
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="places">Places named</label>
        <input
          id="places"
          type="text"
          value={places}
          placeholder="Separated by commas"
          onChange={(event) => setPlaces(event.target.value)}
        />
      </div>
      <div className="field" style={{ marginBottom: 8 }}>
        <label htmlFor="malice">Malicious</label>
        <select id="malice" value={malice} onChange={(event) => setMalice(event.target.value)}>
          <option value="">Not said</option>
          <option value="yes">Suspected</option>
          <option value="no">No</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>
      <div className="field" style={{ marginBottom: 8, maxWidth: "78ch" }}>
        <label htmlFor="said">Message</label>
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
          disabled={!recipient.trim() || !said.trim() || !typedMoment(toldAt) || tell.isPending}
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
      <h3>Response windows</h3>
      {windows.length === 0 && <p className="hint">None declared.</p>}
      {windows.map((each) =>
        editing === each.id ? (
          <WindowForm
            key={each.id}
            window={each}
            windows={windows}
            onDone={done}
            onCancel={() => setEditing(null)}
          />
        ) : (
          <p key={each.id}>
            {each.name}{" "}
            <span className="hint">
              · {each.hours} hours
              {each.from_name ? ` from the first notice for ${each.from_name}` : ""}
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
      {editing === null && <WindowForm windows={windows} onDone={done} />}
    </div>
  );
}

// WindowForm declares a window, or restates one when it is handed it. Every
// field is sent, because a change replaces what the window says.
function WindowForm({
  window,
  windows,
  onDone,
  onCancel,
}: {
  window?: Window;
  windows: Window[];
  onDone: () => void;
  onCancel?: () => void;
}) {
  const [name, setName] = useState(window?.name ?? "");
  const [hours, setHours] = useState(window ? String(window.hours) : "");
  const [lead, setLead] = useState(window?.lead_hours ? String(window.lead_hours) : "");
  const [limited, setLimited] = useState<string[]>(window?.products ?? []);
  const [from, setFrom] = useState(window?.from ? String(window.from) : "");
  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });

  const body = () => ({
    name,
    hours: Number(hours),
    ...(Number(lead) > 0 ? { lead_hours: Number(lead) } : {}),
    ...(limited.length > 0 ? { products: limited } : {}),
    ...(from ? { from: Number(from) } : {}),
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
        setFrom("");
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
      <div className="filters">
        <label className="field">
          <span>Name</span>
          <input
            type="text"
            style={{ width: "32ch" }}
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label className="field" title="Counted from the moment Counted from names">
          <span>Length, hours</span>
          <input
            type="number"
            min={1}
            style={{ width: "12ch" }}
            value={hours}
            onChange={(event) => setHours(event.target.value)}
          />
        </label>
        <label
          className="field"
          title="A second notice this many hours before the end. Leave empty for none"
        >
          <span>Warn, hours before end</span>
          <input
            type="number"
            min={1}
            style={{ width: "12ch" }}
            value={lead}
            onChange={(event) => setLead(event.target.value)}
          />
        </label>
        <label className="field">
          <span>Counted from</span>
          <select
            style={{ width: "auto" }}
            value={from}
            onChange={(event) => setFrom(event.target.value)}
          >
            <option value="">When it became known</option>
            {windows
              .filter((each) => each.id !== window?.id)
              .map((each) => (
                <option key={each.id} value={each.id}>
                  The first notice for {each.name}
                </option>
              ))}
          </select>
        </label>
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
          {window ? "Save" : "Add window"}
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

// Record is the screen's way into the act a finding offers: the same request,
// with the product and the issue asked for rather than read off the finding.
// The issue is typed, with what the product carries offered as it is typed:
// every release kind, every state of support and every row under the triage
// line, because an attack is often on a shipped tag or a release past its end.
// An identifier the list does not hold is still the server's to decide.
function Record({
  products,
  onClose,
}: {
  products: { product: string; name: string }[];
  onClose: () => void;
}) {
  const queries = useQueryClient();
  const [product, setProduct] = useState(products.length === 1 ? (products[0]?.product ?? "") : "");
  const [issue, setIssue] = useState("");
  const term = useDeferredValue(issue.trim());
  const carried = useQuery({
    enabled: product !== "" && term.length >= 3,
    queryKey: ["exploitable", product, term],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: {
            path: { product },
            query: {
              q: term,
              limit: 50,
              on: ["branch", "tag"],
              support: ["in-support", "past-eol"],
              below_floor: true,
            },
          },
        }),
      ),
  });
  // The list is one row per issue and component, so an issue at three
  // components is offered once.
  const offered = useMemo(
    () => [...new Set((carried.data?.items ?? []).map((row) => row.vulnerability))],
    [carried.data],
  );

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3>Record exploited here</h3>
      <Keep
        product={product}
        vulnerability={issue}
        onClose={onClose}
        done={() => {
          void queries.invalidateQueries({ queryKey: ["obligations"] });
          void queries.invalidateQueries({ queryKey: ["finding"] });
        }}
        pick={
          <div className="filters" style={{ marginBottom: 8 }}>
            <label className="field">
              <span>Product</span>
              <select value={product} onChange={(event) => setProduct(event.target.value)}>
                <option value="">Pick a product</option>
                {products.map((each) => (
                  <option key={each.product} value={each.product}>
                    {each.name || each.product}
                  </option>
                ))}
              </select>
            </label>
            <label
              className="field"
              style={{ flex: 1, minWidth: 220 }}
              title="The issue our product was attacked through, by any name it is known under"
            >
              <span>Issue</span>
              <input
                type="text"
                list="exploitable-issues"
                value={issue}
                placeholder="CVE-2026-31431"
                onChange={(event) => setIssue(event.target.value)}
                {...notACredential}
              />
              <datalist id="exploitable-issues">
                {offered.map((each) => (
                  <option key={each} value={each} />
                ))}
              </datalist>
            </label>
          </div>
        }
      />
      {carried.isError && (
        <Failed
          error={carried.error}
          what="What that product carries could not be read. An identifier typed in full still works."
        />
      )}
    </div>
  );
}
