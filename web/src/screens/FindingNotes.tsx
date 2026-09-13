// Notes on the issue in this product, which record no judgment.
//
// The thread that is here whether or not anybody has decided anything. The
// comments beside it hang off a claim, and the box for one appears only where
// a claim already exists — so the first person to say anything had to record a
// judgment in order to say it.
//
// **It says what it is about, in words, above the thread.** It is read beside
// a row that may be one of eleven the same issue sits on, so "this issue in
// this product" is the thing a reader has to be told: not this component, and
// not every product.

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useEditNote, useNote } from "../api/mutations";
import { Failed } from "../ui/Failed";
import { Markdown } from "../ui/Markdown";
import { Editor, forget, mentioning } from "../ui/Editor";
import { initials } from "../ui/initials";
import { Loading } from "../ui/Loading";

export function Notes({
  product,
  vulnerability,
  mine,
  undisclosed,
}: {
  product: string;
  vulnerability: string;
  mine: (who: string) => boolean;
  // Whether the issue has been announced here, which is what decides who may
  // be offered after an @: naming somebody who cannot read it calls them to
  // something they will be refused, and on an undisclosed issue the mention
  // itself says a finding exists.
  undisclosed?: boolean;
}) {
  const [text, setText] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  // Which note's earlier versions are open, where somebody asked.
  const [showing, setShowing] = useState<number | null>(null);
  const note = useNote();
  const draftKey = `note:${product}:${vulnerability}`;
  const notes = useQuery({
    queryKey: ["notes", product, vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/notes", {
          params: { path: { product, vulnerability } },
        }),
      ),
    // Somebody who may not read notes here gets nothing rather than an error
    // on a screen they are otherwise entitled to.
    retry: false,
  });
  const items = notes.data?.items ?? [];
  const about = { product, vulnerability };

  return (
    <div className="card">
      <h3>Notes on this issue</h3>
      <p className="hint" style={{ margin: "0 0 10px" }}>
        About <b>{vulnerability}</b> in <b>{product}</b> — every build of it, and no other product.
        Not about this component: the same issue can sit on several rows here, and a note is on all
        of them. Nothing about a note changes what ranks, a deadline, or what is triaged.
      </p>
      {items.length > 0 && (
        <div className="thread">
          {items.map((each) => (
            <div key={each.id} className="said2">
              <span className="avatar">{initials(each.written_by ?? "")}</span>
              <div>
                <div className="meta">
                  <b>{each.written_by}</b>
                  <span className="when">{each.written_at?.replace("T", " ").slice(0, 16)}</span>
                  {each.edited_at && (
                    <button
                      type="button"
                      className="edited"
                      title="What it said before"
                      aria-expanded={showing === each.id}
                      onClick={() => setShowing(showing === each.id ? null : (each.id ?? null))}
                    >
                      edited
                    </button>
                  )}
                </div>
                {editing === each.id ? (
                  <EditNote
                    id={each.id ?? 0}
                    was={each.body ?? ""}
                    about={about}
                    undisclosed={undisclosed}
                    onDone={() => setEditing(null)}
                  />
                ) : (
                  <div className="bubble">
                    <Markdown source={each.body ?? ""} />
                    {/* What it said before, behind the "edited" mark rather
                        than always on screen: the current text is what a
                        reader is reading, and the history is what somebody
                        checking the record goes looking for. */}
                    {showing === each.id && <EarlierNote id={each.id ?? 0} />}
                    {mine(each.written_by ?? "") && (
                      <button
                        type="button"
                        className="linkish"
                        style={{ marginTop: 6, display: "block" }}
                        onClick={() => setEditing(each.id ?? null)}
                      >
                        Edit
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="field" style={{ margin: "14px 0 0", maxWidth: "78ch" }}>
        <label>Add a note</label>
        <Editor
          value={text}
          onChange={setText}
          draftKey={draftKey}
          rows={4}
          label="Note"
          placeholder="Something whoever decides this should know. No judgment recorded."
          attachTo={about}
          mentions={mentioning(product, undisclosed)}
        />
      </div>
      {note.error != null && <Failed error={note.error} what="That could not be added." />}
      {/* A name that reached nobody. Said without saying why: either no such
          person is recorded or they cannot read this, and telling those apart
          would answer "can this person see undisclosed work" one note at a
          time. The note is kept either way. */}
      {(note.data?.not_notified?.length ?? 0) > 0 && (
        <p className="hint">
          Nobody was told about {note.data?.not_notified?.map((name) => `@${name}`).join(", ")} —
          either there is no such person here, or they cannot read this issue. The note was saved.
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={!text.trim() || note.isPending}
          onClick={() =>
            note.mutate(
              { product, vulnerability, body: text },
              {
                onSuccess: () => {
                  forget(draftKey);
                  setText("");
                },
              },
            )
          }
        >
          Add note
        </button>
        <span className="consequence">Records no judgment</span>
      </div>
    </div>
  );
}

// What a note said before it was changed.
//
// A note goes public at disclosure with the rest of the record, so a record
// whose earlier text is unrecoverable is one somebody can read and nobody can
// check. Read only when asked for.
function EarlierNote({ id }: { id: number }) {
  const history = useQuery({
    queryKey: ["note", id, "history"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/notes/{id}/history", { params: { path: { id } } })),
  });
  const rows = history.data?.items ?? [];
  if (history.isPending) return <Loading />;
  if (rows.length === 0) return null;
  return (
    <div className="earlier">
      {rows.map((row) => (
        <div key={row.version}>
          <span className="hint">
            Version {row.version}, replaced {row.replaced_at?.replace("T", " ").slice(0, 16)}
          </span>
          <Markdown source={row.body ?? ""} />
        </div>
      ))}
    </div>
  );
}

// Rewriting a note in place.
//
// Only its author can, which the server enforces; the button is offered only
// to them so that nobody is invited into a refusal.
//
// No draft is saved. A draft exists so a half-written thought survives a
// sign-out; this one starts as text that is already stored, so keeping a copy
// of it would offer somebody their own note back as an unsent draft.
function EditNote({
  id,
  was,
  onDone,
  about,
  undisclosed,
}: {
  id: number;
  was: string;
  onDone: () => void;
  about: { product: string; vulnerability: string };
  undisclosed?: boolean;
}) {
  const [text, setText] = useState(was);
  const edit = useEditNote();
  return (
    <div className="field" style={{ margin: 0, maxWidth: "78ch" }}>
      <Editor
        value={text}
        onChange={setText}
        rows={4}
        label="Note"
        attachTo={about}
        mentions={mentioning(about.product, undisclosed)}
      />
      {edit.error != null && <Failed error={edit.error} what="That could not be changed." />}
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={!text.trim() || text === was || edit.isPending}
          onClick={() => edit.mutate({ id, body: text }, { onSuccess: onDone })}
        >
          Save
        </button>
        <button type="button" className="btn quiet" onClick={onDone}>
          Cancel
        </button>
      </div>
    </div>
  );
}
