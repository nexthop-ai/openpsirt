import { useEffect, useState } from "react";
import { Failed } from "./Failed";
import { useReseed } from "./reseed";

// Where a decision applies beyond this build, as a guided review.
//
// Two kinds of other build, and only one of them is a choice: builds already
// matching are covered by lookup and are named, not asked about; builds
// holding the issue at another version are offered, because a tick there
// is a claim about code nobody has looked at.
//
// A third kind was declared, rendered and never populated — a build already
// past the fix, shown and not offered. The endpoint splits its answer two
// ways, so the only construction of a plan in the tree passed the empty list
// and the card could not draw whatever the read returned. The document was the
// thing left over rather than the code, so it goes with it; if the endpoint
// grows the bucket the card comes back with it.
//
// What is offered is a version, not a variant, and it says so. The same
// product built two ways is one piece of work — a matching build is reached by
// lookup and never asked about — so anything that reaches this list is here
// because the code differs. Labeling those entries by their build read as
// "approve this for mellanox", which is a question nobody should be asked and
// which made a variant look like a decision somebody had to take twice.
//
// One screen, not one per entry. Walking them individually made a routine
// decision several sheets deep, and the thing being weighed is one line each:
// does the reasoning hold at that version too. They are unticked to start,
// because that is the whole control — a tick is the claim.

export type Other = {
  // One entry per build and version; the build alone is the label.
  key: string;
  build: string;
  stream: string;
  variant: string;
  version: string;
  places: number;
  note: string;
  tone: "ok" | "warn" | "off";
};

export type Plan = {
  build: string;
  covered: number;
  total: number;
  matching: string[];
  offered: Other[];
  reasoning: string;
  versionHere: string;
};

export function Review({
  open,
  plan,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  open: boolean;
  plan: Plan;
  busy: boolean;
  error: unknown;
  onCancel: () => void;
  onConfirm: (applied: Other[]) => void;
}) {
  const [step, setStep] = useState(0);
  const [applied, setApplied] = useState<Set<string>>(() => new Set());
  const n = plan.offered.length;

  // Opened again is the first step again, with nothing ticked.
  useReseed(String(open), () => {
    if (!open) return;
    setStep(0);
    setApplied(new Set());
  });

  // What the sheet does to the page underneath it, which is the document's
  // rather than the sheet's and so belongs in an effect.
  useEffect(() => {
    if (!open) return;
    document.body.dataset.sheet = "open";
    // The keys are the sheet's now, not the field's that opened it.
    (document.activeElement as HTMLElement | null)?.blur?.();
    return () => {
      delete document.body.dataset.sheet;
    };
  }, [open]);

  function go(action: "next" | "back") {
    if (action === "next") setStep((s) => Math.min(1, s + 1));
    else setStep((s) => Math.max(0, s - 1));
  }

  function toggle(key: string, on: boolean) {
    setApplied((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });
  }

  const chosen = plan.offered.filter((o) => applied.has(o.key));

  useEffect(() => {
    if (!open) return;
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onCancel();
        return;
      }
      const tag = (document.activeElement?.tagName ?? "").toUpperCase();
      if (/INPUT|TEXTAREA|SELECT/.test(tag)) return;
      if (event.key === "Enter") {
        event.preventDefault();
        if (step === 0) go("next");
        else if (!busy) onConfirm(chosen);
      } else if (event.key === "ArrowLeft" || event.key === "Backspace") {
        event.preventDefault();
        go("back");
      }
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  });

  if (!open) return null;

  const progress = (
    <div className="revprog">
      {["Where it applies", "Confirm"].map((label, i) => (
        <span key={label} className={i === step ? "on" : i < step ? "done" : ""}>
          {label}
        </span>
      ))}
    </div>
  );

  let title: string;
  let body: React.ReactNode;
  let foot: React.ReactNode;

  if (step === 0) {
    title = "Where this decision applies";
    body = (
      <>
        {progress}
        <div className="revcard">
          <h5>
            This build · <span className="id">{plan.build}</span>
          </h5>
          {/* Consumers rather than places: what a judgment covers here is
              every package of the fold under everything that pulls it in, and
              narrowing is done by consumer. A place count is a number a
              reader cannot reconcile with the control below it. */}
          <p>
            <b>
              {plan.covered} of {plan.total} {plan.total === 1 ? "consumer" : "consumers"}
            </b>
            {plan.covered < plan.total && <> — {plan.total - plan.covered} left open by you</>}.
          </p>
        </div>
        <div className="revcard auto">
          <h5>Covered automatically · {plan.matching.length}</h5>
          <p>
            {plan.matching.length === 0 ? (
              "No other build matches this one's versions and chain."
            ) : (
              <>
                {plan.matching.map((m, i) => (
                  <span key={m}>
                    {i > 0 && ", "}
                    <span className="id">{m}</span>
                  </span>
                ))}
                . Same upstream versions, same chain. A decision reaches these by lookup; nothing is
                copied and there is nothing to agree to.
              </>
            )}
          </p>
        </div>
        <div className="revcard ask">
          <h5>Other versions · {n}</h5>
          {n === 0 ? (
            <p>No other build holds this issue at a different version.</p>
          ) : (
            <>
              <p>
                Different code — <b>a different version</b>, not a different variant. Your reasoning
                is about <span className="id">{plan.versionHere || "the version here"}</span>; tick
                the ones it also holds for. Each lapses on its own.
              </p>
              <ul className="revlist">
                {plan.offered.map((o) => (
                  <li key={o.key}>
                    <label style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                      <input
                        type="checkbox"
                        checked={applied.has(o.key)}
                        onChange={(event) => toggle(o.key, event.target.checked)}
                      />
                      <span>
                        {/* The version leads, because the version is what
                            differs. Led by the build, this read as "approve
                            this for mellanox" — a question about a variant,
                            which is never the question: a build at matching
                            versions is reached by lookup and never appears
                            here at all. */}
                        <span className="id">{o.version || "unstated"}</span>{" "}
                        <span className="hint">
                          {o.build === "this build" ? "also in this build" : `in ${o.build}`} ·{" "}
                          {o.places} {o.places === 1 ? "consumer" : "consumers"}
                        </span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
              <p className="hint" style={{ margin: "6px 0 0" }}>
                Left unticked, each stays open and asks nothing further.
              </p>
              <p className="hint" style={{ margin: "6px 0 0" }}>
                What you wrote:{" "}
                {plan.reasoning.trim()
                  ? plan.reasoning.trim().split("\n")[0]?.slice(0, 160) +
                    (plan.reasoning.length > 160 ? "…" : "")
                  : "(no reasoning written yet)"}
              </p>
            </>
          )}
        </div>
      </>
    );
    foot = (
      <>
        <button type="button" className="btn" onClick={() => go("next")}>
          Review and submit → <kbd className="onbtn">↵</kbd>
        </button>
        <button type="button" className="btn quiet" onClick={onCancel}>
          Cancel
        </button>
        <span className="note">Nothing is written until you confirm</span>
      </>
    );
  } else {
    title = "Confirm";
    const skipped = plan.offered.filter((o) => !applied.has(o.key));
    const records = plan.covered + chosen.reduce((sum, o) => sum + (o.places || 1), 0);
    body = (
      <>
        {progress}
        <div className="revcard">
          <h5>Summary</h5>
          <ul className="revlist">
            <li>
              <b>{plan.covered}</b> {plan.covered === 1 ? "consumer" : "consumers"} in this build
            </li>
            <li>
              <b>{chosen.length}</b> other {chosen.length === 1 ? "version" : "versions"}
              {chosen.length > 0 && (
                <>
                  :{" "}
                  {chosen.map((o, i) => (
                    <span key={o.key}>
                      {i > 0 && ", "}
                      <span className="id">{o.version || "unstated"}</span>{" "}
                      <span className="hint">in {o.build}</span>
                    </span>
                  ))}
                </>
              )}
            </li>
          </ul>
        </div>
        <div className="revcard auto">
          <h5>Matched by lookup</h5>
          <p>
            <b>{plan.matching.length}</b> matching {plan.matching.length === 1 ? "build" : "builds"}
            , by lookup.
          </p>
        </div>
        {skipped.length > 0 && (
          <div className="revcard off">
            <h5>Left undecided</h5>
            <p>
              {skipped.map((o, i) => (
                <span key={o.key}>
                  {i > 0 && ", "}
                  <span className="id">{o.version || "unstated"}</span>{" "}
                  <span className="hint">in {o.build}</span>
                </span>
              ))}{" "}
              — left unticked; each stays open and asks nothing further.
            </p>
          </div>
        )}
        {error != null && <Failed error={error} what="That could not be recorded." />}
        <p className="hint">
          The approver sees this summary, and the count is kept with the approval.
        </p>
      </>
    );
    foot = (
      <>
        <button type="button" className="btn" disabled={busy} onClick={() => onConfirm(chosen)}>
          {busy ? "Recording…" : "Confirm and submit"} <kbd className="onbtn">↵</kbd>
        </button>
        <button type="button" className="btn quiet" disabled={busy} onClick={() => go("back")}>
          ← Back
        </button>
        <span className="note">
          <b>{records}</b> {records === 1 ? "record" : "records"} written
        </span>
      </>
    );
  }

  return (
    <div
      className="backdrop open"
      onClick={(event) => event.target === event.currentTarget && onCancel()}
    >
      <div className="sheet" role="dialog" aria-modal="true" aria-label={title}>
        <header>
          <h3>{title}</h3>
          <button type="button" className="shut" onClick={onCancel}>
            Close (Esc)
          </button>
        </header>
        <div className="body">{body}</div>
        <footer>{foot}</footer>
      </div>
    </div>
  );
}
