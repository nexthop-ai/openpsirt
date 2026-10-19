// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { notACredential } from "../ui/noautofill";
import { WaitingRulings } from "./InboxRuling";
import { UpstreamOffers } from "./QueueOffers";
import { overCapNotice, useBulkCap } from "../ui/bulk";
import { useEffect, useState } from "react";
import { Loading } from "../ui/Loading";
import { Became } from "./QueueMine";
import { ToReaffirm } from "./QueueReaffirm";
import { Embargoes, Ratings } from "./QueuePending";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { UNOWNED_LIST, usePaging } from "./list";
import { claimOf, useAfterClaim, type Claim } from "../api/claims";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Paged } from "../ui/Paged";
import { Count } from "../ui/Count";
import { QueueFilters } from "./QueueFilters";
import { REASONS, wordsFor } from "./queueReasons";
import { fileAt } from "../api/links";
import { Card, Dated } from "./QueueCard";
import { PAGE, useQueueReads } from "./useQueueReads";
import { useQueueApproval } from "./useQueueApproval";

// The review queue at the grain of a claim: one card per proposer's action,
// however many records it wrote. Three lists, one per reason a claim waits:
// for approval, where approving, rejecting and undoing all work at the size of
// the claim; a deferral whose date passed; and a promise whose date passed with
// the finding still open. The last two ask for a new decision rather than an
// agreement, and each card offers only the acts that answer its reason.
export function Queue() {
  const [params, setParams] = useSearchParams();
  const { offset, go } = usePaging();
  // A claim somebody was sent to, by a notice or a link. Found on the page
  // and shown, or said to be missing — a link that lands on the queue with
  // nothing marked leaves somebody hunting through cards for the one meant.
  const wanted = Number(params.get("claim") ?? 0);
  // The claim beside its key, not the key alone. A selection survives paging,
  // because a row is selected by what it is rather than by where it sits, and
  // an approval acts on everything ticked, including what is ticked on another
  // page.
  const [picked, setPicked] = useState<Map<string, Claim>>(new Map());
  // Moving to another tab: the tab's own words set or cleared, the page back
  // to its first, and the selection dropped, because it was made out of the
  // list being replaced.
  function switchTab(changes: Record<string, string | null>) {
    const now = new URLSearchParams(params);
    now.delete("offset");
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) now.delete(key);
      else now.set(key, value);
    }
    setPicked(new Map());
    setParams(now);
  }
  const { cap, over } = useBulkCap(picked.size);
  const {
    batch,
    setBatch,
    justDone,
    setJustDone,
    refused,
    setRefused,
    approveClaim,
    undo,
    approvePicked,
  } = useQueueApproval(picked, setPicked);
  const queries = useQueryClient();
  const afterClaim = useAfterClaim();
  const {
    mine,
    reaffirm,
    aside,
    reason,
    own,
    product,
    narrowing,
    counted,
    queue,
    lapsedMine,
    became,
    embargoes,
    embargoAt,
    setEmbargoAt,
    ratings,
    ratingAt,
    setRatingAt,
  } = useQueueReads(params, offset);

  const found = wanted > 0 && (queue.data?.items ?? []).some((row) => claimOf(row).id === wanted);
  useEffect(() => {
    if (!found) return;
    document.getElementById(`claim-${wanted}`)?.scrollIntoView({ block: "center" });
  }, [found, wanted]);
  // A section somebody was sent to by name — the ratings, the disclosure
  // dates, the rulings — brought into view once it is drawn. A link inside the
  // interface changes the address without loading a page, so the browser does
  // not do it. Each section is drawn when its own read lands, which may be
  // after the queue's, so the page is watched until the section appears.
  const { hash } = useLocation();
  useEffect(() => {
    if (!hash) return;
    const land = () => {
      const section = document.getElementById(hash.slice(1));
      section?.scrollIntoView({ block: "start" });
      return !!section;
    };
    if (land()) return;
    const watch = new MutationObserver(() => {
      if (land()) watch.disconnect();
    });
    watch.observe(document.body, { childList: true, subtree: true });
    return () => watch.disconnect();
  }, [hash]);

  if (queue.isPending) return <Loading />;
  if (queue.isError) {
    return <Failed error={queue.error} what="The review queue could not be read." />;
  }

  // The request the export links make, so a file matches the screen it was
  // taken from rather than being the whole backlog under a narrowed heading.
  const exporting = new URLSearchParams();
  if (!aside && reason !== "approval") exporting.set("reason", reason);
  if (!aside && own && reason !== "approval") exporting.set("mine", "true");
  if (product) exporting.set("product", product);
  if (!aside) {
    for (const [key, value] of Object.entries(narrowing)) {
      for (const each of Array.isArray(value) ? value : [value]) {
        exporting.append(key, String(each));
      }
    }
  }
  const asked = exporting.toString();
  // The file the tab on screen was taken from. Mine lists every claim its
  // reader proposed, whatever became of it, which the queue's own file does
  // not hold; it has a file of its own.
  const file = (format: "csv" | "json") =>
    mine
      ? fileAt("/v1/my-claims.{format}", format)
      : fileAt("/v1/review-queue.{format}", format, { query: asked });
  const claims = (queue.data?.items ?? []).map(claimOf);
  const records = claims.reduce((sum, c) => sum + c.records, 0);
  const words = wordsFor(reason);
  const approving = !aside && reason === "approval";

  return (
    <>
      <div className="screen-head">
        <h2>Review queue</h2>
        <p>
          {reaffirm ? (
            <>
              <Count of={lapsedMine}>{() => (lapsedMine.data?.total ?? 0).toLocaleString()}</Count>{" "}
              lapsed claims of yours · the code moved or the issue was rated worse
            </>
          ) : mine ? (
            <>
              <Count of={became}>{() => (became.data?.total ?? 0).toLocaleString()}</Count> proposed
              by you · what became of each, newest first
            </>
          ) : (
            <>
              {(queue.data?.total ?? claims.length).toLocaleString()} {words.tab.toLowerCase()}
              {records > claims.length && (
                <> · {records.toLocaleString()} records between those shown</>
              )}{" "}
              {product ? (
                <>
                  {" "}
                  · in <b>{product}</b>
                </>
              ) : approving ? (
                <> · across every product you may approve on</>
              ) : (
                <> · across every product you may decide in</>
              )}
            </>
          )}
        </p>
        {/* The list on screen as a file. One row per claim, the way this
            screen counts them, because that is the unit somebody works
            through. There is no file of what is to re-affirm, so that tab
            offers none rather than another list under its heading. */}
        {!reaffirm && (
          <span style={{ marginLeft: "auto" }}>
            <a className="btn quiet" href={file("csv")}>
              CSV
            </a>{" "}
            <a className="btn quiet" href={file("json")}>
              JSON
            </a>
          </span>
        )}
      </div>

      <div className="tabs2">
        {REASONS.map((each) => (
          <button
            key={each.reason}
            type="button"
            className="tab2"
            aria-selected={!aside && reason === each.reason}
            onClick={() =>
              switchTab({
                mine: null,
                reaffirm: null,
                reason: each.reason === "approval" ? null : each.reason,
                ...(each.reason !== reason ? { own: null } : {}),
              })
            }
          >
            {each.tab}{" "}
            <span className="n">
              <Count of={counted[each.reason]}>
                {() => (counted[each.reason].data?.total ?? 0).toLocaleString()}
              </Count>
            </span>
          </button>
        ))}
        <button
          type="button"
          className="tab2"
          aria-selected={mine}
          onClick={() => switchTab({ mine: "1", reaffirm: null, reason: null, own: null })}
        >
          Mine, recent{" "}
          <span className="n">
            <Count of={became}>{() => (became.data?.total ?? 0).toLocaleString()}</Count>
          </span>
        </button>
        <button
          type="button"
          className="tab2"
          aria-selected={reaffirm}
          onClick={() => switchTab({ reaffirm: "1", mine: null, reason: null, own: null })}
        >
          To reaffirm{" "}
          <span className="n">
            <Count of={lapsedMine}>{() => (lapsedMine.data?.total ?? 0).toLocaleString()}</Count>
          </span>
        </button>
      </div>

      {!aside && (
        <QueueFilters
          params={params}
          onAsk={(next) => {
            // A selection is made out of the list being replaced.
            setPicked(new Map());
            setRefused(0);
            setParams(next);
          }}
        />
      )}
      {/* The two lists that show everybody's claims, narrowed to the
          reader's own. The approvals never hold the reader's own. */}
      {!aside && !approving && (
        <label className="check" style={{ marginBottom: 10 }}>
          <input
            type="checkbox"
            checked={own}
            onChange={(event) => {
              const now = new URLSearchParams(params);
              if (event.target.checked) now.set("own", "1");
              else now.delete("own");
              now.delete("offset");
              setParams(now);
            }}
          />
          Mine only
        </label>
      )}

      {wanted > 0 && !found && (
        <div className="alert" style={{ marginBottom: 10 }}>
          <strong>Claim {wanted} is not waiting here.</strong>
          <span>
            It may have been decided, or it may sit on another page.{" "}
            <Link to={UNOWNED_LIST} className="linkish">
              Unassigned →
            </Link>
          </span>
        </div>
      )}

      {approving && claims.length > 0 && (
        <div className="batchbar">
          <label style={{ display: "flex", gap: 7, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={claims.length > 0 && claims.every((c) => picked.has(c.key))}
              onChange={(event) => {
                // This page either way, so ticking and unticking are
                // inverses and the rest of the selection stands.
                const next = new Map(picked);
                for (const claim of claims) {
                  if (event.target.checked) next.set(claim.key, claim);
                  else next.delete(claim.key);
                }
                setPicked(next);
              }}
              aria-label="Select every claim shown"
            />
            <b>{picked.size === 0 ? "Nothing selected" : `${picked.size} selected`}</b>
          </label>
          <span className="hint">Approvals under one batch name can be undone together.</span>
          <span className="spacer" />
          <input
            {...notACredential}
            type="text"
            value={batch}
            onChange={(event) => setBatch(event.target.value)}
            placeholder="batch name"
            aria-label="Batch name"
            style={{ width: 150 }}
          />
          {/* Bounded by what this deployment allows in one act, and said
              rather than met one refusal at a time: approving is a request
              per claim, and this selection deliberately survives paging, so
              it can be arbitrarily large. */}
          {over && (
            <span className="alert" role="status">
              {overCapNotice(cap)}
            </span>
          )}
          <button
            type="button"
            className="btn"
            disabled={picked.size === 0 || approveClaim.isPending || over}
            onClick={() => void approvePicked()}
          >
            {picked.size === 0 ? "Approve selected" : `Approve ${picked.size} selected`}
          </button>
        </div>
      )}

      {refused > 0 && (
        <p className="alert" role="status">
          {refused === 1
            ? "One claim could not be agreed to and is still selected."
            : `${refused.toLocaleString()} claims could not be agreed to and are still selected.`}
        </p>
      )}
      {approveClaim.error != null && (
        <Failed error={approveClaim.error} what="That could not be approved." />
      )}
      {undo.error != null && (
        <Failed error={undo.error} what="That agreement could not be taken back." />
      )}

      {/* Taking a batch back. Offered only just after one was made, because
          this is the moment somebody notices — a permanent control for
          undoing something named at some point in the past is a control
          nobody can use safely. The decisions themselves stand; only the
          agreements are undone, and each proposer is told. */}
      {justDone && (
        <div className="alert info" style={{ marginBottom: 12 }}>
          <strong>Agreed to under &ldquo;{justDone}&rdquo;</strong>
          <span>Returns those claims to this queue. Each proposer is notified.</span>
          <button
            type="button"
            className="linkish"
            disabled={undo.isPending}
            onClick={() => undo.mutate(justDone)}
          >
            Undo the batch
          </button>
          <button type="button" className="linkish" onClick={() => setJustDone("")}>
            Dismiss
          </button>
        </div>
      )}

      {reaffirm ? (
        <ToReaffirm
          rows={lapsedMine.data?.items ?? []}
          query={lapsedMine}
          onDone={() => {
            void queries.invalidateQueries({ queryKey: ["to-reaffirm"] });
            afterClaim();
          }}
        />
      ) : mine ? (
        <Became rows={became.data?.items ?? []} query={became} />
      ) : claims.length === 0 ? (
        <Empty title="Nothing is waiting here." detail={words.empty} />
      ) : !approving ? (
        <div className="queue">
          {claims.map((claim) => (
            <Dated key={claim.key} claim={claim} reason={reason} marked={claim.id === wanted} />
          ))}
        </div>
      ) : (
        <div className="queue">
          {claims.map((claim) => (
            <Card
              key={claim.key}
              claim={claim}
              marked={claim.id === wanted}
              picked={picked.has(claim.key)}
              onPick={(on) => {
                const next = new Map(picked);
                if (on) next.set(claim.key, claim);
                else next.delete(claim.key);
                setPicked(next);
              }}
            />
          ))}
        </div>
      )}
      <Paged
        shown={
          reaffirm
            ? (lapsedMine.data?.items?.length ?? 0)
            : mine
              ? (became.data?.items?.length ?? 0)
              : claims.length
        }
        total={reaffirm ? lapsedMine.data?.total : mine ? became.data?.total : queue.data?.total}
        offset={offset}
        limit={PAGE}
        onGo={go}
      />

      <Ratings
        waiting={(ratings.data?.items ?? []).filter((each) => each.needs_approval)}
        total={ratings.data?.total}
        offset={ratingAt}
        onGo={setRatingAt}
        error={ratings.isError ? ratings.error : undefined}
      />

      {/* The movement read is deliberately quiet for somebody who may read
          nothing undisclosed — an empty list rather than a refusal — so only a
          real failure is handed on. */}
      <Embargoes
        waiting={embargoes.data?.items ?? []}
        total={embargoes.data?.total}
        offset={embargoAt}
        onGo={setEmbargoAt}
        error={embargoes.isError ? embargoes.error : undefined}
      />

      {/* A ruling setting reports aside waits for a second person the way a
          dismissal does, and this is where somebody goes to be one. Narrowed
          to the products the reader may work reports in. */}
      <WaitingRulings product={product || undefined} />

      {/* An upstream's statement that depends on its own build waits for a
          person the way a claim does, and this is where somebody finds it. */}
      <UpstreamOffers product={product || undefined} />
    </>
  );
}
