import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, type Body } from "../api/client";

// AssessmentRow is one claim about how bad an issue is.
type AssessmentRow = Body<"AssessmentBody">;
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Severity } from "../ui/Severity";

// The two things waiting for a second person that are not claims.
//
// An embargo extension and a severity rating both hide risk on one person's
// say-so unless somebody agrees, which is why they are in the review queue at
// all — and neither is a claim about code, so neither shares the card, the
// selection or the batch that the claims use. They are here together because
// what they have in common is exactly that.

// Embargo extensions waiting for a second person.
//
// **The reason is the whole of what is being agreed to.** An extension moves a
// date somebody outside could hold us to, and the only thing distinguishing a
// judgment from a habit is why — so the reason leads and the dates follow it.
//
// **A request of your own is shown and cannot be agreed to.** The person who
// asked may not be the one who agrees, which is the control the threshold
// exists to reach; hiding it would leave somebody hunting for what is holding
// their case up.
export function Embargoes({ waiting }: { waiting: Body<"PendingExtensionBody">[] }) {
  const queries = useQueryClient();
  const agree = useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.POST("/v1/disclosure-extensions/{id}/approval", { params: { path: { id } } }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["extensions"] }),
  });

  if (waiting.length === 0) return null;

  return (
    <>
      <div className="screen-head" id="embargoes" style={{ marginTop: 22 }}>
        <h2>Extension requests</h2>
        <p>
          {waiting.length.toLocaleString()} · somebody has asked to keep something hidden longer
          than this deployment allows on one person&rsquo;s word. Reaching the date discloses
          nothing by itself; what is being agreed to is how long it stays hidden.
        </p>
      </div>
      {agree.error != null && <Failed error={agree.error} what="That could not be agreed to." />}
      <div className="queue">
        {waiting.map((row) => (
          <div className="card" key={row.id}>
            <div className="cardhead">
              <span className="id">{row.vulnerability}</span>
              <span className="hint">
                {row.product} · asked by {row.by}
                {row.mine && <> · yours</>}
              </span>
            </div>
            <p className="reading">{row.reason}</p>
            <p className="hint">
              Ends <b>{row.was}</b> → <b>{row.until}</b> · {(row.days ?? 0).toLocaleString()} days
              longer.
            </p>
            <div className="cardfoot">
              <button
                type="button"
                className="btn"
                disabled={agree.isPending || row.mine}
                title={
                  row.mine
                    ? "You asked for this one. The person who asks may not be the one who agrees"
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
    </>
  );
}

// Ratings of issues waiting for a second person.
//
// A milder rating hides things, so it waits the way a dismissal does — and
// there was nowhere to be that second person, because the route existed and no
// screen reached it.
//
// **What it says beyond "agree or not" is the point.** Rating something milder
// pushes its deadline out, which is what the second person is there for. But
// where a product has said what it considers worth triaging at all, a rating
// that crosses that line does something different in kind: the findings stop
// being work rather than becoming later work, and they carry no deadline at
// all. Those are two different things to agree to, and an approver was shown
// neither.
export function Ratings({ waiting }: { waiting: AssessmentRow[] }) {
  const queries = useQueryClient();
  const agree = useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.POST("/v1/assessments/{id}/agreement", { params: { path: { id } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["queue"] }),
  });

  if (waiting.length === 0) return null;

  return (
    <>
      <div className="screen-head" id="ratings" style={{ marginTop: 22 }}>
        <h2>Ratings awaiting approval</h2>
        <p>
          {waiting.length.toLocaleString()} · somebody says an issue is milder than the world does.
          A rating of ours holds wherever the issue appears, so it waits for a second person.
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
            <p className="reading">{row.reasoning}</p>
            <p className="hint">
              {(row.open ?? 0).toLocaleString()} open{" "}
              {(row.open ?? 0) === 1 ? "finding" : "findings"} you can see, in{" "}
              {(row.in_products ?? 0).toLocaleString()}{" "}
              {(row.in_products ?? 0) === 1 ? "product" : "products"}.
            </p>
            {(row.off_the_list ?? 0) > 0 ? (
              <p className="alert" style={{ margin: "6px 0 0" }}>
                <strong>
                  This takes {(row.off_the_list ?? 0).toLocaleString()} of them off the working list
                  in {(row.off_the_list_in_products ?? 0).toLocaleString()}{" "}
                  {(row.off_the_list_in_products ?? 0) === 1 ? "product" : "products"}.
                </strong>
                <span>
                  Below what a product considers worth triaging, a finding is still recorded,
                  counted and reportable — and it carries no deadline. You are agreeing that it is
                  not work, rather than that it is later work.
                </span>
              </p>
            ) : (
              <p className="hint" style={{ margin: "6px 0 0" }}>
                Still above what every product here triages from, so this makes them later work
                rather than no work.
              </p>
            )}
            <div className="cardfoot">
              <button
                type="button"
                className="btn"
                disabled={agree.isPending}
                onClick={() => agree.mutate(row.id ?? 0)}
              >
                Agree
              </button>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
