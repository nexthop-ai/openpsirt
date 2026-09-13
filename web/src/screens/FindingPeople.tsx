// Who is involved with this finding, and what hangs off it.
//
// Collaborators brought into an undisclosed case, whoever is holding the work,
// closing a recorded flaw by hand, the files attached to it and the words
// people have marked it with.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { Failed } from "../ui/Failed";
import { Holder, type Held } from "../ui/Holder";
import { Suggest } from "../ui/Suggest";
import { offeredAs, whoIs } from "../ui/whom";

// Who has been brought into one undisclosed case.
//
// **Being on a case is not reading the product.** A collaborator sees this
// issue wherever it sits here and nothing else, may argue about it, and may
// not agree to anybody's claim — which is said on the card rather than
// discovered when a button refuses, because it is the reason the grant is
// safe to give.
//
// Managed by whoever reads the case rather than by an administrator: knowing
// who is needed on a case is knowing the case, and routing it through somebody
// who does not read it makes them the bottleneck on every embargo.
export function Collaborators({
  product,
  vulnerability,
}: {
  product: string;
  vulnerability: string;
}) {
  const queries = useQueryClient();
  const [adding, setAdding] = useState("");
  const on = useQuery({
    queryKey: ["collaborators", product, vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/collaborators", {
          params: { path: { product, vulnerability } },
        }),
      ),
    // Somebody who may not read undisclosed work here is refused, and that is
    // an answer rather than a fault: the card stays quiet on their screen.
    retry: false,
  });
  // Who can be offered. The people who already read this product at all —
  // bringing somebody into a case grants access to somebody who has some, and
  // cannot bring anybody into the deployment.
  //
  // Narrowed by what is typed, in the server, which is where the whole list
  // is: the endpoint has always taken a term and this picker simply never
  // sent one, so it asked for a hundred people and offered whichever hundred
  // came back.
  const people = useQuery({
    queryKey: ["mentionable", product, false, adding.trim()],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/mentionable", {
          params: {
            path: { product },
            query: { limit: 100, ...(adding.trim() ? { q: adding.trim() } : {}) },
          },
        }),
      ),
  });
  const bring = useMutation({
    mutationFn: async (identity: string) =>
      unwrap(
        await api.PUT("/v1/products/{product}/issues/{vulnerability}/collaborators/{identity}", {
          params: { path: { product, vulnerability, identity } },
        }),
      ),
    onSuccess: () => {
      setAdding("");
      void queries.invalidateQueries({ queryKey: ["collaborators"] });
    },
  });
  const take = useMutation({
    mutationFn: async (identity: string) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/issues/{vulnerability}/collaborators/{identity}", {
          params: { path: { product, vulnerability, identity } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["collaborators"] }),
  });

  if (on.isError) return null;
  const rows = on.data?.items ?? [];
  const already = new Set(rows.map((row) => row.identity));
  // Whoever may be offered and is not already on the case.
  const offerable = (people.data?.items ?? []).filter((person) => !already.has(person.identity));
  const who = whoIs(adding, offerable);

  return (
    <div className="card">
      <h3>Collaborators</h3>
      <p className="reading" style={{ marginBottom: 8 }}>
        {rows.length === 0
          ? "Nobody has been brought in."
          : `${rows.length} ${rows.length === 1 ? "person has" : "people have"} been brought in.`}{" "}
        Grants read and comment on this issue only. Cannot agree to claims.
      </p>
      {bring.error != null && <Failed error={bring.error} what="They could not be brought in." />}
      {take.error != null && <Failed error={take.error} what="They could not be taken off." />}
      {rows.length > 0 && (
        <span className="variants" style={{ marginBottom: 8 }}>
          {rows.map((row) => (
            <span key={row.identity} className="vchip" title={`Brought in by ${row.added_by}`}>
              {row.name || row.identity}{" "}
              <button
                type="button"
                className="linkish"
                style={{ fontSize: "inherit" }}
                title="Take them off this case"
                disabled={take.isPending}
                onClick={() => take.mutate(row.identity ?? "")}
              >
                ×
              </button>
            </span>
          ))}
        </span>
      )}
      {/* Typed against who may be offered, rather than a select over a
          hundred of them in whatever order they came back. Add stays disabled
          until what is typed resolves to one of them — bringing somebody in
          grants access, and a name matching nobody is refused by the server
          either way. */}
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <Suggest
          id="bring-in"
          label="Somebody to bring in"
          value={adding}
          onChange={setAdding}
          options={offerable.map(offeredAs)}
          loading={people.isFetching}
          from={0}
          placeholder="somebody…"
          disabled={bring.isPending}
        />
        <button
          type="button"
          className="btn quiet"
          disabled={who === "" || bring.isPending}
          onClick={() => bring.mutate(who)}
        >
          Add collaborator
        </button>
      </div>
      <p className="hint" style={{ marginTop: 8 }}>
        They are notified. Logged as an access change.
      </p>
    </div>
  );
}

export function Assignee({
  at,
  assigned,
  undisclosed,
  routedBy,
}: {
  at: {
    product: string;
    stream: string;
    variant: string;
    vulnerability: string;
    component: string;
  };
  assigned: string;
  undisclosed: boolean;
  // Which standing rule placed this, where one did. A placement nobody can
  // explain is one nobody can correct.
  routedBy: string;
}) {
  const queries = useQueryClient();
  const me = useWho();
  const hand = useMutation({
    // A party, not a person: a team holds work exactly as somebody does , and
    // the picker offers both.
    mutationFn: async (held: Held | null) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/assignment",
          {
            params: { path: at },
            body:
              held === null
                ? {}
                : held.kind === "team"
                  ? { team: held.identity }
                  : { person: held.identity },
          },
        ),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["finding"] });
      void queries.invalidateQueries({ queryKey: ["findings"] });
      void queries.invalidateQueries({ queryKey: ["unassigned"] });
      void queries.invalidateQueries({ queryKey: ["holdings"] });
    },
  });

  return (
    <div className="within">
      <h4>Assignee</h4>
      {routedBy && (
        <p
          className="hint"
          style={{ marginBottom: 8 }}
          title="Taking it is picking up unassigned work"
        >
          Placed by <b>{routedBy}</b>
        </p>
      )}
      {hand.error != null && <Failed error={hand.error} what="That could not be recorded." />}
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <div style={{ minWidth: 240 }}>
          <Holder
            product={at.product}
            undisclosed={undisclosed}
            value={assigned ? { identity: assigned } : null}
            disabled={hand.isPending}
            onPick={(held) => hand.mutate(held)}
          />
        </div>
        {/* Taking unowned work is a triager's own, and it is the common case.
            The API always allowed it; there was no way to ask. */}
        {me.data?.identity != null && assigned !== me.data.identity && (
          <button
            type="button"
            className="btn quiet"
            disabled={hand.isPending}
            onClick={() => hand.mutate({ kind: "person", identity: me.data!.identity, name: "" })}
          >
            {/* The same word the unassigned list's batch bar uses, because it
                is the same act: taking work nobody holds. */}
            Take this
          </button>
        )}
        {hand.isPending && <span className="hint">Recording…</span>}
      </div>
      <p className="hint" style={{ margin: "8px 0 0" }} title="Set it to nobody to unassign">
        Applies to every build with this component
      </p>
    </div>
  );
}

// Closing a flaw somebody recorded, because it is fixed in this build.
//
// Only here, and only on a recorded flaw. Everywhere else resolution is
// computed from scans, which is what stops a fix being reported that shipped in
// nobody's release. A flaw recorded by hand is the one case with no such
// evidence and no prospect of any — no scan reports it — so a person closes it
// or nothing does.
export function Resolve({
  at,
  vulnerability,
}: {
  at: { product: string; stream: string; variant: string };
  vulnerability: string;
}) {
  const queries = useQueryClient();
  const [open, setOpen] = useState(false);
  const [because, setBecause] = useState("");

  const close = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/resolve",
          {
            params: { path: { ...at, vulnerability } },
            body: { because: because.trim() },
          },
        ),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["finding"] });
      void queries.invalidateQueries({ queryKey: ["findings"] });
      setOpen(false);
    },
  });

  return (
    <div className="card">
      <h3>Fixed here</h3>
      <p className="reading" style={{ marginBottom: 8 }}>
        Scans never found this, so only you can close it. Closes every place here, and
        <b>nothing reopens it</b>.
      </p>
      {close.error != null && <Failed error={close.error} what="That could not be closed." />}
      {!open ? (
        <button type="button" className="btn quiet" onClick={() => setOpen(true)}>
          Close as fixed…
        </button>
      ) : (
        <>
          <div className="field">
            <label htmlFor="res-because">
              What fixed it{" "}
              <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--sev-high)" }}>
                required
              </span>
            </label>
            <textarea
              id="res-because"
              value={because}
              placeholder="The authentication check added in 1.0.1, shipped in this build."
              onChange={(event) => setBecause(event.target.value)}
              style={{ minHeight: 80 }}
            />
            <span className="hint">Required.</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={because.trim() === "" || close.isPending}
              onClick={() => close.mutate()}
            >
              {close.isPending ? "Closing…" : "Close as fixed"}
            </button>
            <button type="button" className="btn quiet" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// What text about this issue refers to.
//
// Listed as well as rendered inline, because a file referred to from a
// revision nobody is reading now is still part of the record — and because
// somebody who has to take one back out needs to find it without hunting
// through every justification for the reference.
export function Attachments({
  about,
  admin,
}: {
  about: { product: string; vulnerability: string };
  admin: boolean;
}) {
  const queries = useQueryClient();
  const listed = useQuery({
    queryKey: ["attachments", about],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/attachments", {
          params: { path: about },
        }),
      ),
  });
  const [removing, setRemoving] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const redact = useMutation({
    mutationFn: async ({ token, why }: { token: string; why: string }) =>
      unwrap(
        await api.DELETE("/v1/attachments/{token}", {
          params: { path: { token } },
          body: { reason: why },
        }),
      ),
    onSuccess: async () => {
      setRemoving(null);
      setReason("");
      await queries.invalidateQueries({ queryKey: ["attachments"] });
    },
  });

  const files = listed.data?.items ?? [];
  // Nothing attached is the ordinary case, and a heading over an empty list
  // is a screen asking a question nobody had.
  if (files.length === 0) return null;

  return (
    <section className="panel" style={{ marginTop: 14 }}>
      <h3>Attached files</h3>
      <ul className="files">
        {files.map((file) => (
          <li key={file.token}>
            {file.redacted ? (
              <>
                <span className="hint">
                  <b>{file.filename}</b> was removed
                  {file.redacted_reason ? <> — {file.redacted_reason}</> : null}
                </span>
              </>
            ) : (
              <>
                <a href={`/v1/attachments/${file.token}`} rel="noreferrer">
                  {file.filename}
                </a>
                <span className="hint">
                  {" "}
                  · {file.content_type} · {Math.max(1, Math.round((file.size ?? 0) / 1024))} KB
                </span>
                {admin && removing !== file.token && (
                  <button
                    type="button"
                    className="btn quiet"
                    style={{ marginLeft: 8 }}
                    onClick={() => setRemoving(file.token ?? null)}
                  >
                    Remove
                  </button>
                )}
              </>
            )}
            {removing === file.token && (
              <div className="field" style={{ margin: "6px 0 0", maxWidth: "60ch" }}>
                <label>Why it is being removed</label>
                <input
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder="A credential was pasted into it"
                />
                <p className="hint">The file is deleted. The record of it stays.</p>
                <div className="actions">
                  <button
                    type="button"
                    className="btn"
                    disabled={!reason.trim() || redact.isPending}
                    onClick={() => redact.mutate({ token: file.token ?? "", why: reason })}
                  >
                    Remove the file
                  </button>
                  <button type="button" className="btn quiet" onClick={() => setRemoving(null)}>
                    Cancel
                  </button>
                </div>
                {redact.error != null && (
                  <Failed error={redact.error} what="That file could not be removed." />
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

// The words people put on a finding.
//
// **People mark work regardless.** With nowhere to put it they do it inside
// the reasoning text, where nothing can filter on it and an approver reads it
// as part of the argument.
//
// **What is offered is what people have written**, not a vocabulary this
// screen invented: the list comes from the product, so the second person to
// reach for "waiting on vendor" spells it the way the first one did, and the
// two are one filter rather than two.
//
// **Marking is triage**, so somebody who may only read is shown the marks and
// not the control. A control that is offered and then refused teaches people
// to distrust the ones that work.
export function Marks({
  at,
  tags,
  mayMark,
  onChanged,
}: {
  at: {
    product: string;
    stream: string;
    variant: string;
    vulnerability: string;
    component: string;
  };
  tags: string[];
  mayMark: boolean;
  onChanged: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [adding, setAdding] = useState(false);

  const inUse = useQuery({
    queryKey: ["tags", at.product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/tags", {
          params: { path: { product: at.product } },
        }),
      ),
    enabled: mayMark && adding,
  });

  const path = (tag: string) => ({ ...at, tag });
  const mark = useMutation({
    mutationFn: async (tag: string) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/tags/{tag}",
          { params: { path: path(tag) } },
        ),
      ),
    onSuccess: () => {
      setTyped("");
      setAdding(false);
      onChanged();
    },
  });
  const unmark = useMutation({
    mutationFn: async (tag: string) =>
      unwrap(
        await api.DELETE(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/tags/{tag}",
          { params: { path: path(tag) } },
        ),
      ),
    onSuccess: onChanged,
  });

  const busy = mark.isPending || unmark.isPending;
  // What is already on this is not offered again — the request would succeed
  // and change nothing, which reads as the control not working.
  const already = new Set(tags.map((each) => each.trim().toLowerCase()));
  const offered = (inUse.data?.items ?? []).filter((each) => !already.has(each.toLowerCase()));

  if (tags.length === 0 && !mayMark) return null;
  return (
    <div className="marks">
      {tags.map((tag) => (
        <span key={tag} className="mark">
          {tag}
          {mayMark && (
            <button
              type="button"
              aria-label={`Remove tag ${tag}`}
              title={`Remove tag ${tag}`}
              disabled={busy}
              onClick={() => unmark.mutate(tag)}
            >
              ×
            </button>
          )}
        </span>
      ))}
      {mayMark &&
        (adding ? (
          <span className="marking">
            <Suggest
              id="tag-with"
              label="Add a tag"
              value={typed}
              onChange={setTyped}
              onPick={(tag) => mark.mutate(tag)}
              options={offered}
              loading={inUse.isFetching}
              from={0}
              placeholder="waiting on vendor"
              disabled={busy}
            />
            <button
              type="button"
              className="btn quiet"
              disabled={typed.trim() === "" || busy}
              onClick={() => mark.mutate(typed.trim())}
            >
              Add
            </button>
            <button
              type="button"
              className="linkish"
              onClick={() => {
                setTyped("");
                setAdding(false);
              }}
            >
              Cancel
            </button>
          </span>
        ) : (
          <button type="button" className="mark add" onClick={() => setAdding(true)}>
            + Tag
          </button>
        ))}
      {(mark.error != null || unmark.error != null) && (
        <Failed error={mark.error ?? unmark.error} what="That tag did not change." />
      )}
    </div>
  );
}
