import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useScope } from "../../app/scope";
import { scopeWords } from "./catalog";

// The frame every named report is drawn in.
//
// One frame rather than a heading typed into each report, because what makes a
// sheet checkable is the same on all of them: what was asked for, what it was
// asked of, and when it was taken. A report that states two of the three is a
// page somebody cannot compare against anything later.
//
// It prints. The stylesheet is the record's — the shell, the rail and the
// controls drop out, a header states the question and the moment, and a row
// does not break across a page.
export function Sheet({
  name,
  answers,
  asked,
  settled = true,
  children,
}: {
  name: string;
  answers: string;
  // What was asked for beyond the scope, where the report has controls of its
  // own. The controls themselves do not print, so a sheet whose figures cover
  // ninety days and does not say so is a sheet nobody can check.
  asked?: string;
  // Whether every figure on it has arrived. A printed sheet is a record, and
  // this one stamps the moment it was taken on itself — so a sheet printed
  // while its reads are in flight, or after one of them failed, is a dated
  // document stating figures nobody computed.
  settled?: boolean;
  children: ReactNode;
}) {
  const at = useScope();
  const taken = new Date().toISOString().slice(0, 16).replace("T", " ");

  return (
    <>
      {/* Not on paper: the printed header below states the same thing and
          states it fully, and a sheet carrying both reads as two titles. */}
      <div className="screen-head noprint">
        <h2>{name}</h2>
        <p>
          {scopeWords(at)} — {answers}
        </p>
        <span style={{ marginLeft: "auto" }} className="noprint">
          <Link className="linkish" to="/reports">
            All reports
          </Link>{" "}
          <button
            type="button"
            className="btn"
            disabled={!settled}
            title={settled ? undefined : "Some of these figures have not arrived"}
            onClick={() => window.print()}
          >
            Print
          </button>
        </span>
      </div>

      {/* Only on paper, and the reason the sheet can be checked: a printed
          report has to say what it is a report of, what it was asked of, and
          when it was taken. */}
      <div className="printhead">
        <h1>OpenPSIRT — {name}</h1>
        <p>
          {scopeWords(at)}
          {asked ? ` · ${asked}` : ""} · taken {taken}Z
        </p>
      </div>

      {children}
    </>
  );
}
