// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";

import { useRevise, useWithdraw } from "../api/mutations";
import { Editor, forget, mentioning } from "./Editor";
import { Failed } from "./Failed";
import { Markdown } from "./Markdown";
import { restore } from "../app/drafts";

// The words a decision rests on, and the two things that can be done to them.
//
// One control with one set of consequences, drawn by the decision's own screen
// and by the finding it was made about. Whether Revise and Withdraw are
// offered is decided here, from the decision's state, so both screens offer the
// same acts to the same person about the same decision.
//
// Revising keeps the old words readable, takes back the approval given for
// them, and returns the decision to the queue. Withdrawing needs nobody.

// The words that are finished, and so have nothing left to revise or withdraw.
//
// Said as what is over rather than as what is open, so a word this list does
// not name falls with the open ones, which is the direction a missing case
// should fall.
const FINISHED = new Set(["withdrawn", "lapsed"]);

// The text a revision opens with: the draft left from an earlier attempt,
// where there is one, and the standing reasoning otherwise. The editor
// restores a draft only over an empty field, so opening on the standing text
// would write it over the draft.
export function revisionStart(draftKey: string, reasoning: string): string {
  return restore(draftKey) || reasoning;
}

// revisable reports whether a decision in this state may still be revised or
// withdrawn. The words are the ones the record uses for what became of a
// decision, and the ones the API reports as a decision's state.
export function revisable(state: string): boolean {
  return state !== "" && !FINISHED.has(state);
}

export function ReasonEditor({
  decisionId,
  reasoning,
  state,
  approved,
  about,
  onDone,
  spaced = false,
  undisclosed,
  internal,
  writes = true,
}: {
  decisionId: number;
  reasoning: string;
  // The decision's fate, as the record words it. Whether revising and
  // withdrawing are offered is decided here from that, rather than by each
  // screen deciding for itself.
  state: string;
  // The consequence line's own words, which differ for a decision somebody has
  // already agreed to.
  approved: boolean;
  about: { product: string; vulnerability: string };
  onDone: () => void;
  spaced?: boolean;
  // The disclosure of the thing being argued about, which decides who
  // may be offered after an @. This is the same text the decision form writes.
  undisclosed?: boolean;
  // Whether it is internal material: a code finding's, until its flaw is disclosed.
  internal?: boolean;
  // Whether the reader may revise and withdraw it, which a reader of a moved
  // code finding's decision through its flaw may not.
  writes?: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(reasoning);
  const revise = useRevise();
  const withdraw = useWithdraw();
  const draftKey = `revise:${decisionId}`;
  const above = spaced ? { marginTop: 12 } : undefined;

  return (
    <>
      {editing ? (
        <div style={{ ...above, maxWidth: "78ch" }}>
          <div className="alert" style={{ marginBottom: 10 }}>
            <strong>Revising the reasoning withdraws the approval</strong>
            <span>
              The earlier text stays in the revision history. The decision returns to the queue.
            </span>
          </div>
          <Editor
            value={text}
            onChange={setText}
            draftKey={draftKey}
            label="Reasoning"
            attachTo={about}
            mentions={mentioning(about.product, undisclosed, internal)}
          />
          {revise.error != null && <Failed error={revise.error} what="That could not be stored." />}
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={!text.trim() || revise.isPending}
              onClick={() =>
                revise.mutate(
                  { id: decisionId, reasoning: text },
                  {
                    onSuccess: () => {
                      forget(draftKey);
                      setEditing(false);
                      onDone();
                    },
                  },
                )
              }
            >
              Save revision
            </button>
            <button type="button" className="btn quiet" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="why rendered" style={above}>
          {reasoning ? <Markdown source={reasoning} /> : <p className="hint">Nothing written.</p>}
        </div>
      )}

      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That could not be withdrawn." />
      )}
      {writes && revisable(state) && !editing && (
        <div className="actions" style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn ghost"
            onClick={() => {
              setText(revisionStart(draftKey, reasoning));
              setEditing(true);
            }}
          >
            Revise reasoning
          </button>
          <button
            type="button"
            className="btn quiet"
            disabled={withdraw.isPending}
            onClick={() => withdraw.mutate({ id: decisionId }, { onSuccess: onDone })}
          >
            Withdraw
          </button>
          <span className="consequence">
            {approved
              ? "Revising withdraws the approval; withdrawing needs nobody"
              : "Withdrawing needs nobody"}
          </span>
        </div>
      )}
    </>
  );
}
