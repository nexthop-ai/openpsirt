// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type Body } from "../api/client";

// AssessmentRow is one claim about how bad an issue is.
type AssessmentRow = Body<"AssessmentBody">;
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Paged } from "../ui/Paged";
import { Severity } from "../ui/Severity";

// The two things waiting for a second person that are not claims.
//
// A movement of a disclosure date and a severity rating both hide risk on one
// person's say-so unless somebody agrees, which is why they are in the review
// queue at all — and neither is a claim about code, so neither shares the card, the
// selection or the batch that the claims use. They are here together because
// what they have in common is exactly that.

// said is how many there are, or the page length where the server reported no
// total.
//
// A page length printed bare is a count of the page rather than of the list,
// and the reader has no way to tell which they are looking at — so where the
// figure is the page's, the pager under the section is what says so. Both
// routes here do report a total; the fallback is for a response that somehow
// carries none, and it is never the whole story on its own.
function said(shown: number, total?: number): string {
  if (total != null && total > 0) return total.toLocaleString();
  return shown.toLocaleString();
}

// The rows one request of either section carries, matching what the queue
// asks for. Named here so the pager and the request cannot disagree.
export const PENDING_PAGE = 50;

// Movements of a disclosure date waiting for a second person.
//
// The reason is the whole of what is being agreed to. A movement changes a
// date somebody outside could hold us to, and the only thing distinguishing a
// judgment from a habit is why — so the reason leads and the dates follow it.
//
// Which act it is leads the dates, because an embargo ending later and one
// ending sooner are different things to agree to.
//
// A request of your own is shown and cannot be agreed to. The person who
// asked may not be the one who agrees, which is the control the threshold
// exists to reach; hiding it would leave somebody hunting for what is holding
// their case up.
export function Embargoes({
  waiting,
  total,
  offset = 0,
  onGo,
  error,
}: {
  waiting: Body<"PendingMovementBody">[];
  // The number waiting in all. Without it the page length is printed as the
  // figure, so the fifty-first request was not in the number and nothing said
  // so.
  total?: number;
  // The offset this page starts at, and the controls that move it. Without them
  // the heading said the real total over fifty rows and the fifty-first was
  // counted and unreachable.
  offset?: number;
  onGo?: (offset: number) => void;
  // A failed read, so the section says so rather than drawing nothing. Absent
  // and empty look identical, and empty is the ordinary state here.
  error?: unknown;
}) {
  const queries = useQueryClient();
  const agree = useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.POST("/v1/disclosure-movements/{id}/approval", { params: { path: { id } } }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["movements"] }),
  });

  if (error != null) {
    return (
      <div style={{ marginTop: 22 }}>
        <Failed error={error} what="Requests to move a disclosure date could not be read." />
      </div>
    );
  }
  if (waiting.length === 0) return null;

  return (
    <>
      <div className="screen-head" id="embargoes" style={{ marginTop: 22 }}>
        <h2>Disclosure dates</h2>
        <p>
          {said(waiting.length, total)} · somebody has asked to move a date or disclose an issue,
          and it needs a second person. Reaching the date discloses nothing by itself.
        </p>
      </div>
      {agree.error != null && <Failed error={agree.error} what="That could not be agreed to." />}
      <div className="queue">
        {waiting.map((row) => (
          <div className="card" key={row.id}>
            <div className="cardhead">
              <span className="id">{row.vulnerability}</span>
              <span className="hint">
                {row.product} · asked by {row.by_name || row.by}
                {row.mine && <> · yours</>}
              </span>
            </div>
            <p className="reading">{row.reason}</p>
            {row.act === "disclosure" ? (
              <p className="hint">
                Disclose · the issue becomes public in {row.product}. This can&rsquo;t be undone.
              </p>
            ) : (
              <p className="hint">
                {row.act === "shortening" ? "Brought forward" : "Extended"} · ends <b>{row.was}</b>{" "}
                → <b>{row.until}</b> · {(row.days ?? 0).toLocaleString()} days
                {row.act === "shortening" ? " sooner" : " longer"}.
              </p>
            )}
            <div className="cardfoot">
              <button
                type="button"
                className="btn"
                disabled={agree.isPending || row.mine}
                title={
                  row.mine
                    ? "You asked for this one. The person who asks may not be the one who agrees"
                    : row.act === "disclosure"
                      ? "Agree, and make it public"
                      : "Agree, and move the date"
                }
                onClick={() => agree.mutate(row.id ?? 0)}
              >
                Agree
              </button>
              {row.mine && (
                <span className="note">Waiting on somebody else — you asked for this one</span>
              )}
            </div>
          </div>
        ))}
      </div>
      <Paged
        shown={waiting.length}
        total={total}
        offset={offset}
        limit={PENDING_PAGE}
        onGo={onGo}
      />
    </>
  );
}

// Ratings of issues waiting for a second person.
//
// A milder rating hides things, so it waits the way a dismissal does — and
// there was nowhere to be that second person, because the route existed and no
// screen reached it.
//
// The point is what it says beyond "agree or not". Rating something milder
// pushes its deadline out, which is what the second person is there for. But
// where a product has said what it considers worth triaging at all, a rating
// that crosses that line does something different in kind: the findings stop
// being work rather than becoming later work, and they carry no deadline at
// all. Those are two different things to agree to, and an approver was shown
// neither.
//
// Each row names its product, because a rating belongs to one and two
// products may rate the same issue differently. A row saying only "CVE-… low"
// is a word an approver cannot act on: what they are agreeing to is a deadline
// and a triage line in one named place.
export function Ratings({
  waiting,
  total,
  offset = 0,
  onGo,
  error,
}: {
  waiting: AssessmentRow[];
  total?: number;
  offset?: number;
  onGo?: (offset: number) => void;
  error?: unknown;
}) {
  const queries = useQueryClient();
  const agree = useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.POST("/v1/assessments/{id}/agreement", { params: { path: { id } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["queue"] }),
  });

  if (error != null) {
    return (
      <div style={{ marginTop: 22 }}>
        <Failed error={error} what="Ratings awaiting approval could not be read." />
      </div>
    );
  }
  if (waiting.length === 0) return null;

  return (
    <>
      <div className="screen-head" id="ratings" style={{ marginTop: 22 }}>
        <h2>Ratings awaiting approval</h2>
        <p>
          {said(waiting.length, total)} · somebody says an issue is milder than the world does. A
          rating holds in every build of the product it was made for, so it waits for a second
          person.
        </p>
      </div>
      {agree.error != null && <Failed error={agree.error} what="That could not be agreed to." />}
      <div className="queue">
        {waiting.map((row) => (
          <div className="card" key={row.id}>
            <div className="cardhead">
              <span className="id">{row.vulnerability}</span>
              <span>
                <Severity word={row.published ?? ""} /> → <Severity word={row.severity ?? ""} />
              </span>
            </div>
            <p className="hint" style={{ margin: "0 0 6px" }}>
              In <b>{row.product_name || row.product}</b> — and nowhere else.
            </p>
            <p className="reading">{row.reasoning}</p>
            <p className="hint">
              {(row.open ?? 0).toLocaleString()} open{" "}
              {(row.open ?? 0) === 1 ? "finding" : "findings"} you can see in{" "}
              {row.product_name || row.product}.
            </p>
            {(row.off_the_list ?? 0) > 0 ? (
              <p className="alert" style={{ margin: "6px 0 0" }}>
                <strong>
                  This takes {(row.off_the_list ?? 0).toLocaleString()} of them off the working list
                  in {row.product_name || row.product}.
                </strong>
                <span>
                  Still recorded and counted, but with no deadline. You are agreeing this is not
                  work, rather than later work.
                </span>
              </p>
            ) : (
              <p className="hint" style={{ margin: "6px 0 0" }}>
                Still above what {row.product_name || row.product} triages from, so this makes them
                later work rather than no work.
              </p>
            )}
            <div className="cardfoot">
              {/* The same rule the extensions above hold to, and the same
                  reason: the server refuses your own either way, so offering
                  the button means a click that answers 422 and says nothing
                  about why. */}
              <button
                type="button"
                className="btn"
                disabled={agree.isPending || row.mine}
                title={
                  row.mine
                    ? "You made this rating. The person who proposes may not be the one who agrees"
                    : `Agree, and put the rating in force in ${row.product_name || row.product || "this product"}`
                }
                onClick={() => agree.mutate(row.id ?? 0)}
              >
                Agree
              </button>
              {row.mine && <span className="hint">Yours, so somebody else agrees to it.</span>}
            </div>
          </div>
        ))}
      </div>
      <Paged
        shown={waiting.length}
        total={total}
        offset={offset}
        limit={PENDING_PAGE}
        onGo={onGo}
      />
    </>
  );
}
