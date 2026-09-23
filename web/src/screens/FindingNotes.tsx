// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Notes on the issue in this product, which record no judgment.
//
// The thread that is here whether or not anybody has decided anything. The
// comments beside it hang off a claim, and the box for one appears only where
// a claim already exists — so the first person to say anything had to record a
// judgment in order to say it.
//
// It says what it is about, in words, above the thread. It is read beside
// a row that may be one of eleven the same issue sits on, so "this issue in
// this product" is the thing a reader has to be told: not this component, and
// not every product.

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import { notYours, unwrap } from "../api/queries";
import { useEditNote, useNote } from "../api/mutations";
import { Failed } from "../ui/Failed";
import { Thread } from "../ui/Thread";
import { Editor, mentioning } from "../ui/Editor";

export function Notes({
  product,
  vulnerability,
  mine,
  undisclosed,
}: {
  product: string;
  vulnerability: string;
  mine: (who: string) => boolean;
  // The issue's disclosure here, which is what decides who may
  // be offered after an @: naming somebody who cannot read it calls them to
  // something they will be refused, and on an undisclosed issue the mention
  // itself says a finding exists.
  undisclosed?: boolean;
}) {
  const note = useNote();
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
  const about = { product, vulnerability };
  // A refusal is an answer — somebody may not read notes here — and the card
  // stays quiet about it. A read that failed is not, and drawing an empty
  // thread with a live composer above it invites somebody to write into a
  // conversation whose existing notes they were never shown.
  const unread = notes.isError && !notYours(notes.error);

  return (
    <div className="card">
      <h3>Notes on this issue</h3>
      <p className="hint" style={{ margin: "0 0 10px" }}>
        <b>{vulnerability}</b> in <b>{product}</b>, all builds. Not tied to a component, and changes
        nothing.
      </p>
      <Thread
        items={notes.data?.items ?? []}
        mine={mine}
        about={about}
        undisclosed={undisclosed}
        word="Note"
        consequence="Records no judgment"
        placeholder="Something whoever decides this should know. No judgment recorded."
        draftKey={`note:${product}:${vulnerability}`}
        notNotified={note.data?.not_notified ?? []}
        unread={
          unread ? (
            <Failed error={notes.error} what="The notes on this issue could not be read." />
          ) : null
        }
        adding={note}
        onAdd={(body, done) => note.mutate({ product, vulnerability, body }, { onSuccess: done })}
        edit={(piece, done) => (
          <EditNote
            id={piece.id ?? 0}
            was={piece.body ?? ""}
            about={about}
            undisclosed={undisclosed}
            onDone={done}
          />
        )}
        history={useNoteHistory}
      />
    </div>
  );
}

// One note's earlier versions, as the thread asks for them. The endpoint is
// the only thing a note thread and a comment thread do not share.
function useNoteHistory(id: number) {
  return useQuery({
    queryKey: ["note", id, "history"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/notes/{id}/history", { params: { path: { id } } })),
  });
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

// The same thread, on the screen that spans products.
//
// A product at a time, because a note belongs to one and this screen shows
// an issue wherever it sits. One thread merging what several teams wrote would
// be the deployment-wide record a per-product note exists to avoid — and a
// reader could not tell which product any line of it was about.
export function IssueNotes({
  vulnerability,
  products,
  mine,
}: {
  vulnerability: string;
  // The products carrying this issue, as the rows give them: the name to ask
  // with, what to call it on screen, and whether anything of it here is still
  // undisclosed.
  products: { name: string; called: string; undisclosed: boolean }[];
  mine: (who: string) => boolean;
}) {
  const [product, setProduct] = useState(products[0]?.name ?? "");
  const chosen = products.find((each) => each.name === product) ?? products[0];
  if (!chosen) return null;

  return (
    <>
      {products.length > 1 && (
        <div className="field" style={{ margin: "12px 0 0", maxWidth: "40ch" }}>
          <label htmlFor="notes-product">Notes for</label>
          <select
            id="notes-product"
            value={product}
            onChange={(event) => setProduct(event.target.value)}
          >
            {products.map((each) => (
              <option key={each.name} value={each.name}>
                {each.called}
              </option>
            ))}
          </select>
        </div>
      )}
      <Notes
        key={chosen.name}
        product={chosen.name}
        vulnerability={vulnerability}
        mine={mine}
        undisclosed={chosen.undisclosed}
      />
    </>
  );
}
