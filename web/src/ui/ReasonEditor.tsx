import { useState } from "react";

import { useRevise, useWithdraw } from "../api/mutations";
import { Editor, forget } from "./Editor";
import { Failed } from "./Failed";
import { Markdown } from "./Markdown";

// The words a claim rests on, and the two things that can be done to them.
//
// One control with one set of consequences, drawn by the claim's own screen
// and by the finding it was made about. It was written twice, and the two
// copies had already drifted: one said revising returns "the claim" to the
// review queue and the other "the decision", and the claim is what returns.
// The authorization divergence the review found lives in exactly this block
// too — so the gate is decided by whoever draws it, once, and passed in.
//
// Revising keeps the old words readable, takes back the approval given for
// them, and returns the claim to the queue. Withdrawing needs nobody.
// What is finished, and therefore has nothing left to revise or withdraw.
//
// Said as what is over rather than as what is open, because the two screens
// that draw this control reach the claim by different routes and had each
// written their own list of the open words: one allowed waiting, sent back,
// undone and approved, and the other only proposed and approved — so a claim
// an approver agreed to in part and set aside in part offered Revise and
// Withdraw on one screen and neither on the other, to the same person about
// the same claim. A word neither list had thought of belongs with the open
// ones, which is the direction a missing case should fall.
const FINISHED = new Set(["withdrawn", "lapsed"]);

// revisable reports whether a claim in this state may still be revised or
// withdrawn. The words are the ones the record uses for what became of a
// claim, and the ones the API reports as a decision's state.
export function revisable(state: string): boolean {
  return state !== "" && !FINISHED.has(state);
}

export function ReasonEditor({
  claimId,
  reasoning,
  state,
  approved,
  about,
  onDone,
  spaced = false,
}: {
  claimId: number;
  reasoning: string;
  // What became of the claim, as the record words it. Whether revising and
  // withdrawing are offered is decided here from that, rather than by each
  // screen deciding for itself.
  state: string;
  // What the consequence line says, which differs for a claim somebody has
  // already agreed to.
  approved: boolean;
  about: { product: string; vulnerability: string };
  onDone: () => void;
  spaced?: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(reasoning);
  const revise = useRevise();
  const withdraw = useWithdraw();
  const draftKey = `revise:${claimId}`;
  const above = spaced ? { marginTop: 12 } : undefined;

  return (
    <>
      {editing ? (
        <div style={{ ...above, maxWidth: "78ch" }}>
          <div className="alert" style={{ marginBottom: 10 }}>
            <strong>Revising the reasoning withdraws the approval</strong>
            <span>
              The earlier words stay readable in the revision history, and the claim returns to the
              review queue marked as previously approved.
            </span>
          </div>
          <Editor
            value={text}
            onChange={setText}
            draftKey={draftKey}
            label="Reasoning"
            attachTo={about}
          />
          {revise.error != null && <Failed error={revise.error} what="That could not be stored." />}
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={!text.trim() || revise.isPending}
              onClick={() =>
                revise.mutate(
                  { id: claimId, reasoning: text },
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
      {revisable(state) && !editing && (
        <div className="actions" style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn ghost"
            onClick={() => {
              setText(reasoning);
              setEditing(true);
            }}
          >
            Revise reasoning
          </button>
          <button
            type="button"
            className="btn quiet"
            disabled={withdraw.isPending}
            onClick={() => withdraw.mutate({ id: claimId }, { onSuccess: onDone })}
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
