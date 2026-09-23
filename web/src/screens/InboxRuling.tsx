import { mayOf, useWho } from "../app/session";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  PAGE,
  type Rulable,
  type Ruling,
  useApproveRuling,
  useRule,
  useRulingsAcross,
  useWithdrawRuling,
} from "../api/intake";
import { Paged } from "../ui/Paged";
import { overCapNotice, useBulkCap } from "../ui/bulk";
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
  // The server refuses a ruling past what one act may write, so the button is
  // held back and the reason said rather than met as a refusal.
  const { cap, over } = useBulkCap(references.length);

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
          disabled={!ready(asTyped) || over || rule.isPending}
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
      {over && (
        <p className="alert" role="status">
          {overCapNotice(cap)}
        </p>
      )}
      {rule.error != null && <Failed error={rule.error} what="Nothing was ruled." />}
    </div>
  );
}

// One ruling: what it says, about which reports, and where it stands.
//
// Named by its product wherever it is read outside that product's inbox, and
// without its controls in the record, which is read and printed rather than
// worked.
export function RulingCard({
  ruling,
  named = false,
  record = false,
}: {
  ruling: Ruling;
  named?: boolean;
  record?: boolean;
}) {
  const product = ruling.product;
  const approve = useApproveRuling(product);
  const withdraw = useWithdrawRuling(product);
  // Agreeing and withdrawing are different rights from reading, and from each
  // other: an approver who reads undisclosed work may agree and may not send
  // a ruling back, which is working the reports.
  const may = mayOf(useWho().data, product);
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
        {named && (
          <>
            <Link to={`/products/${encodeURIComponent(product)}/inbox`}>{product}</Link> ·{" "}
          </>
        )}
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

      {!record && ruling.state !== "withdrawn" && (
        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          {ruling.state === "waiting" && !ruling.yours && may?.may_approve_rulings && (
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
            hidden={!may?.may_hide}
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

// The rulings waiting for a second person, across every product the reader
// may work reports in, for the review queue.
export function WaitingRulings({ product }: { product?: string }) {
  const [offset, setOffset] = useState(0);
  const listed = useRulingsAcross({
    waiting: true,
    products: product ? [product] : [],
    offset,
  });
  useBackOff(listed.data?.items?.length, offset, setOffset);
  if (listed.isError) {
    return (
      <div style={{ marginTop: 22 }}>
        <Failed
          error={listed.error}
          what="The rulings on vulnerability reports could not be read."
        />
      </div>
    );
  }
  const rows = listed.data?.items ?? [];
  const total = listed.data?.total ?? rows.length;
  if (total === 0) return null;
  return (
    <>
      <div className="screen-head" id="rulings" style={{ marginTop: 22 }}>
        <h2>
          Rulings on vulnerability reports <span className="n">{total.toLocaleString()}</span>
        </h2>
        <p>Vulnerability reports proposed as rejected or out of scope.</p>
      </div>
      {rows.map((ruling) => (
        <RulingCard key={ruling.id} ruling={ruling} named />
      ))}
      <Paged shown={rows.length} total={total} offset={offset} limit={PAGE} onGo={setOffset} />
    </>
  );
}

// useBackOff steps a paged list back a page when the page it is on has
// emptied under it — approving or withdrawing the last row on a later page —
// so a list with rows still in it never reads as empty.
export function useBackOff(
  shown: number | undefined,
  offset: number,
  setOffset: (offset: number) => void,
) {
  useEffect(() => {
    if (shown === 0 && offset > 0) setOffset(Math.max(0, offset - PAGE));
  }, [shown, offset, setOffset]);
}
