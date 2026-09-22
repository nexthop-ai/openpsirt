import { useState } from "react";
import { Link } from "react-router-dom";
import {
  type Rulable,
  type Ruling,
  useApproveRuling,
  useRule,
  useWithdrawRuling,
} from "../api/intake";
import { Editor } from "../ui/Editor";
import { notACredential } from "../ui/noautofill";
import { Failed } from "../ui/Failed";
import { Markdown } from "../ui/Markdown";
import { on } from "../ui/when";
import { dispositionSaid, needsReason, needsSecond, RULABLE, ready } from "./inbox";

// Saying what one or more reports are, where the answer is not an issue here.
//
// One form for one report and for a selection, because the server takes a
// ruling over any number of them and the second person approves the whole
// selection as one act.
export function RuleForm({
  product,
  references,
  onDone,
}: {
  product: string;
  references: string[];
  onDone?: () => void;
}) {
  const [disposition, setDisposition] = useState<Rulable | "">("");
  const [reasoning, setReasoning] = useState("");
  const [duplicateOf, setDuplicateOf] = useState("");
  const rule = useRule(product);
  const asTyped = { disposition, reasoning, duplicateOf };
  const many = references.length > 1;

  return (
    <div>
      <div className="seg" role="group" aria-label="Disposition">
        {RULABLE.map((each) => (
          <button
            key={each}
            type="button"
            aria-pressed={disposition === each}
            onClick={() => setDisposition(each)}
          >
            {dispositionSaid(each)}
          </button>
        ))}
      </div>

      {disposition === "duplicate" && (
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="duplicate-of">Duplicate of</label>
          <input
            {...notACredential}
            id="duplicate-of"
            type="text"
            value={duplicateOf}
            placeholder="CVE-2026-0001"
            onChange={(event) => setDuplicateOf(event.target.value)}
          />
          <span className="hint">
            An issue open in {product}. For a closed one, reject instead.
          </span>
        </div>
      )}

      {disposition !== "" && (
        <div className="field" style={{ marginTop: 10 }}>
          <Editor
            label={needsReason(disposition) ? "Reason" : "Reason (optional)"}
            value={reasoning}
            onChange={setReasoning}
            rows={4}
            draftKey={`ruling:${product}:${references.join(",")}`}
            mentions={{ product, visibility: "private" }}
          />
        </div>
      )}

      {disposition !== "" && needsSecond(disposition) && (
        <p className="hint" style={{ margin: "6px 0 0" }}>
          Takes effect when somebody else approves.
        </p>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button
          type="button"
          className="btn"
          disabled={!ready(asTyped) || rule.isPending}
          onClick={() =>
            disposition &&
            rule.mutate(
              {
                reports: references,
                disposition,
                ...(reasoning.trim() ? { reasoning: reasoning.trim() } : {}),
                ...(disposition === "duplicate" ? { duplicate_of: duplicateOf.trim() } : {}),
              },
              {
                onSuccess: () => {
                  setDisposition("");
                  setReasoning("");
                  setDuplicateOf("");
                  onDone?.();
                },
              },
            )
          }
        >
          {disposition !== "" && needsSecond(disposition) ? "Propose" : "Submit"}
          {many ? ` for ${references.length}` : ""}
        </button>
      </div>
      {rule.error != null && <Failed error={rule.error} what="Nothing was ruled." />}
    </div>
  );
}

// One ruling: what it says, about which reports, and where it stands.
export function RulingCard({ product, ruling }: { product: string; ruling: Ruling }) {
  const approve = useApproveRuling(product);
  const withdraw = useWithdrawRuling(product);
  const at = `/products/${encodeURIComponent(product)}/inbox`;
  const state =
    ruling.state === "waiting"
      ? { said: "Waiting for approval", tone: "waiting" }
      : ruling.state === "withdrawn"
        ? { said: "Withdrawn", tone: "lapsed" }
        : { said: "In force", tone: "agreed" };

  return (
    <div className="card" style={{ marginBottom: 10 }}>
      <p style={{ margin: 0 }}>
        <b>{dispositionSaid(ruling.disposition)}</b>{" "}
        <span className={`state ${state.tone}`}>{state.said}</span>
        {ruling.duplicate_of && (
          <>
            {" "}
            · of{" "}
            <Link className="id" to={`/issues/${encodeURIComponent(ruling.duplicate_of)}`}>
              {ruling.duplicate_of}
            </Link>
          </>
        )}
      </p>
      <p className="hint" style={{ margin: "4px 0 0" }}>
        {ruling.proposed_by}, {on(ruling.proposed_at)}
        {ruling.approved_by && (
          <>
            {" "}
            · approved by {ruling.approved_by}, {on(ruling.approved_at)}
          </>
        )}
        {ruling.withdrawn_by && (
          <>
            {" "}
            · withdrawn by {ruling.withdrawn_by}, {on(ruling.withdrawn_at)}
          </>
        )}
      </p>
      {ruling.reasoning && <Markdown source={ruling.reasoning} className="reading" />}
      <p style={{ margin: "6px 0 0", display: "flex", flexWrap: "wrap", gap: 6 }}>
        {(ruling.reports ?? []).map((reference) => (
          <Link key={reference} className="id" to={`${at}/${encodeURIComponent(reference)}`}>
            {reference}
          </Link>
        ))}
      </p>

      {ruling.state !== "withdrawn" && (
        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          {ruling.state === "waiting" && !ruling.yours && (
            <button
              type="button"
              className="btn"
              disabled={approve.isPending}
              onClick={() => approve.mutate(ruling.id)}
            >
              Approve
            </button>
          )}
          <button
            type="button"
            className="btn quiet"
            disabled={withdraw.isPending}
            title="Returns every report it covers to the inbox"
            onClick={() => withdraw.mutate(ruling.id)}
          >
            {ruling.state === "waiting" ? (ruling.yours ? "Withdraw" : "Send back") : "Undo"}
          </button>
        </div>
      )}
      {approve.error != null && <Failed error={approve.error} what="It was not approved." />}
      {withdraw.error != null && <Failed error={withdraw.error} what="It was not withdrawn." />}
    </div>
  );
}
