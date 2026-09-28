// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState, type ReactNode } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { Editor, forget, mentioning } from "./Editor";
import { Failed } from "./Failed";
import { Loading } from "./Loading";
import { Markdown } from "./Markdown";
import { initials } from "./initials";
import { at } from "./when";

// A conversation about one thing, however that thing is addressed.
//
// The comments on a claim and the notes on an issue are the same thread: the
// avatar and the author line, the timestamp, the edited mark, the earlier
// versions behind it, the editor in place, the draft, and the note about a
// name that reached nobody. Written out twice, one tab apart, the two would
// diverge, and a fix to the timestamp would land in whichever file the author
// had open.
//
// The endpoint is what genuinely differs, and it stays with each caller: the
// query, the two mutations and the history read arrive as props rather than
// being built here from a word.

type Said = {
  id?: number;
  body?: string;
  written_by?: string;
  written_by_name?: string;
  written_at?: string;
  edited_at?: string;
};

// said is how a moment on a thread is written: to the minute, in UTC and
// saying so, as every moment quoted across time zones is.
export function said(moment?: string): string {
  return at(moment);
}

export function Thread({
  items,
  mine,
  about,
  undisclosed,
  word,
  consequence,
  placeholder,
  draftKey,
  notNotified,
  unread,
  adding,
  onAdd,
  edit,
  history,
}: {
  items: Said[];
  // A piece written by whoever is reading. The identity alone: a
  // display name anybody can be given would make ownership turn on a label.
  mine: (writtenBy: string) => boolean;
  about: { product: string; vulnerability: string };
  undisclosed?: boolean;
  // The name for one piece, and what adding one does not do. The two words
  // that are genuinely a caller's, so the wording stays deliberate rather than
  // drifting together by accident.
  word: "Comment" | "Note";
  consequence: string;
  placeholder: string;
  draftKey: string;
  // Names nobody was told about, said without saying why.
  notNotified: string[];
  // A read that failed, as against one the server refused. The second is an
  // answer and stays quiet; the caller decides which this is.
  unread?: ReactNode;
  adding: { isPending: boolean; error: unknown };
  onAdd: (body: string, done: () => void) => void;
  edit: (piece: Said, done: () => void) => ReactNode;
  history: (id: number) => UseQueryResult<{ items?: Version[] | null }>;
}) {
  const [text, setText] = useState("");
  const [showing, setShowing] = useState<number | null>(null);
  const [editing, setEditing] = useState<number | null>(null);
  const lower = word.toLowerCase();

  return (
    <>
      {unread}
      {items.length > 0 && (
        <div className="thread">
          {items.map((each) => (
            <div key={each.id} className="said2">
              <span className="avatar">
                {initials(each.written_by_name || each.written_by || "")}
              </span>
              <div>
                <div className="meta">
                  <b>{each.written_by_name || each.written_by}</b>
                  <span className="when">{said(each.written_at)}</span>
                  {each.edited_at && (
                    <button
                      type="button"
                      className="edited"
                      title="Its earlier wording"
                      aria-expanded={showing === each.id}
                      onClick={() => setShowing(showing === each.id ? null : (each.id ?? null))}
                    >
                      edited
                    </button>
                  )}
                </div>
                {editing === each.id ? (
                  edit(each, () => setEditing(null))
                ) : (
                  <div className="bubble">
                    <Markdown source={each.body ?? ""} />
                    {/* What it said before. Behind the "edited" mark rather
                        than always on screen: the current text is what a
                        reader is reading, and the history is what somebody
                        checking the record goes looking for. */}
                    {showing === each.id && <Earlier history={history(each.id ?? 0)} />}
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
        <label>Add a {lower}</label>
        <Editor
          value={text}
          onChange={setText}
          draftKey={draftKey}
          rows={4}
          label={word}
          placeholder={placeholder}
          attachTo={about}
          mentions={mentioning(about.product, undisclosed)}
        />
      </div>
      {adding.error != null && <Failed error={adding.error} what="That could not be added." />}
      {/* A name that reached nobody. Said without saying why: either no such
          person is recorded or they cannot read this, and telling those apart
          would answer "can this person see undisclosed work" one piece at a
          time. The text is kept either way — losing a paragraph to fix a word
          is the wrong trade. */}
      {notNotified.length > 0 && (
        <p className="hint">
          Nobody was told about {notNotified.map((name) => `@${name}`).join(", ")} — either there is
          no such person here, or they cannot read this. The {lower} was saved.
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={!text.trim() || adding.isPending}
          onClick={() =>
            onAdd(text, () => {
              forget(draftKey);
              setText("");
            })
          }
        >
          {word}
        </button>
        <span className="consequence">{consequence}</span>
      </div>
    </>
  );
}

type Version = { version?: number; body?: string; replaced_at?: string };

// A piece's earlier wording, before it was changed.
//
// A thread goes public at disclosure with the rest of the record, so one whose
// earlier text is unrecoverable is one somebody can read and nobody can check.
// Read only when asked for: the current text is what a reader is reading, and
// this is what somebody checking goes looking for — which is why the query
// arrives already built rather than being made here.
function Earlier({ history }: { history: UseQueryResult<{ items?: Version[] | null }> }) {
  const rows = history.data?.items ?? [];
  if (history.isPending) return <Loading />;
  if (history.isError) {
    return <Failed error={history.error} what="The earlier wording could not be read." />;
  }
  if (rows.length === 0) return null;
  return (
    <div className="earlier">
      {rows.map((row) => (
        <div key={row.version}>
          <span className="hint">
            Version {row.version}, replaced {said(row.replaced_at)}
          </span>
          <Markdown source={row.body ?? ""} />
        </div>
      ))}
    </div>
  );
}

// Rewriting one piece of a thread in place.
//
// Only its author can, which the server enforces; the button is offered only
// to them so that nobody is invited into a refusal. What it said before is
// kept and readable behind the "edited" mark.
//
// No draft is saved. A draft exists so a half-written thought survives a
// sign-out; this one starts as text that is already stored, so keeping a copy
// of it would offer somebody their own words back as an unsent draft.
//
// The write is the caller's, as the thread's other endpoints are: a comment
// and a note differ in where they are saved and in nothing drawn here.
export function EditPiece({
  id,
  was,
  label,
  useEdit,
  onDone,
  about,
  undisclosed,
}: {
  id: number;
  was: string;
  label: string;
  useEdit: () => {
    mutate: (piece: { id: number; body: string }, then: { onSuccess: () => void }) => void;
    error: unknown;
    isPending: boolean;
  };
  onDone: () => void;
  about: { product: string; vulnerability: string };
  undisclosed?: boolean;
}) {
  const [text, setText] = useState(was);
  const edit = useEdit();
  return (
    <div className="field" style={{ margin: 0, maxWidth: "78ch" }}>
      <Editor
        value={text}
        onChange={setText}
        rows={4}
        label={label}
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
