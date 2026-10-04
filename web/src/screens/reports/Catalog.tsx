// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { askForScope, useScope } from "../../app/scope";
import { GROUPS, ON_SCREENS, leadsTo, scopeWords, type Needs, type Report } from "./catalog";

// The catalog of named reports.
//
// What somebody means by a report is one of three things — a question with a
// name, a file to send to somebody without an account here, or a question
// nobody had a name for.
//
// So: the named ones first, grouped by what they answer, then the rail screens
// that answer a named question, then the two files that exist nowhere else.
// Each named report is a page of its own, which is what makes it printable,
// linkable and quotable — a section of a dashboard is none of those.
//
// The third is the findings list, not a panel here. A screen offering the
// findings list's filters and query is that list at a second address, and the
// copy is always the poorer one.
export function Catalog() {
  const at = useScope();

  return (
    <>
      <div className="screen-head">
        <h2>Reports</h2>
        <p>{scopeWords(at)}</p>
      </div>

      <section className="panel">
        <h3>Named reports</h3>
        <div className="catalog-groups">
          {GROUPS.map((group) => (
            <div key={group.name} className="catalog-group">
              <h4>{group.name}</h4>
              <ul className="files catalog">
                {group.reports.map((report) => (
                  <Entry key={report.slug ?? report.name} report={report} />
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* Screens on the rail, listed because a question with a name is looked
          for here. Kept apart from the reports so the catalog does not read as
          twice the reporting there is. */}
      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Also on screens</h3>
        <ul className="files catalog catalog-strip">
          {ON_SCREENS.map((report) => (
            <Entry key={report.name} report={report} />
          ))}
        </ul>
      </section>

      {/* Only what is reachable nowhere else. The record of judgments, the
          review queue, the by-component view, the comparison and the register
          are all files offered on the screen that produces them, and those
          copies are the better ones because they carry that screen's filters. */}
      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Files</h3>
        <p className="hint">
          Other files are offered on the screen that answers for them. These two have no screen of
          their own.
        </p>
        <ul className="files catalog">
          <li>
            <div>
              What is <b>running out of time</b> — <a href="/v1/running-out.csv?days=30">CSV</a> ·{" "}
              <a href="/v1/running-out.json?days=30">JSON</a>
            </div>
            <div className="hint">
              Open, undecided and due within 30 days. <span className="id">?days=</span> takes up to
              a year.
            </div>
          </li>
          {at.product && at.stream && at.variant ? (
            <li>
              {/* What a customer's own scanner reads. Advisories are about
                  flaws in our own product; this is the document third-party
                  components belong in. */}
              <div>
                A <b>VEX document</b> for <b>{at.stream}</b> · <b>{at.variant}</b> —{" "}
                <a href={vexAt(at.product, at.stream, at.variant)}>OpenVEX</a>
              </div>
              <div className="hint">
                For a customer&rsquo;s own scanner. Approved dismissals and public findings only.
              </div>
            </li>
          ) : (
            <li>
              <div className="catalog-name">
                <Pick name="A VEX document" needs="build" />
              </div>
              <div className="hint">For a customer&rsquo;s own scanner. One per build.</div>
            </li>
          )}
        </ul>
      </section>

      {/* The question nobody had a name for is asked where the filters live,
          rather than on a second copy of that screen. Drawn as a catalog entry
          because that is what it is: a link over a line saying what it answers,
          and a link inside hint text reads as hint text. */}
      <section className="panel" style={{ marginTop: 14 }}>
        <h3>Anything else</h3>
        <ul className="files catalog">
          <li>
            <div>
              <Link to="/findings">The findings list</Link>
            </div>
            <div className="hint">
              For anything else, narrow the findings list and export it from there.
            </div>
          </li>
        </ul>
      </section>
    </>
  );
}

// One row of the catalog: its name, and what it answers beneath it.
//
// A row that cannot answer at the selection is still drawn, because a report
// missing from a list reads as a report that does not exist. Its name opens the
// scope picker, and a tag beside it says what to pick — kept out of the line
// beneath, where it would read as part of the description.
function Entry({ report }: { report: Report }) {
  const at = useScope();
  const { to, needs } = leadsTo(report, at);
  return (
    <li>
      <div className="catalog-name">
        {to ? (
          <Link to={to}>{report.name}</Link>
        ) : needs ? (
          <Pick name={report.name} needs={needs} />
        ) : (
          <b>{report.name}</b>
        )}
      </div>
      <div className="hint">{report.answers}</div>
    </li>
  );
}

// The words on the tag of an entry that needs a scope.
const NEEDS: Record<Needs, { tag: string; pick: string }> = {
  product: { tag: "Needs a product", pick: "Pick a product" },
  build: { tag: "Needs a build", pick: "Pick a product, a branch or tag, and a variant" },
};

// The name of an entry waiting on a scope, with the tag saying which. One
// control: either half opens the scope picker.
function Pick({ name, needs }: { name: string; needs: Needs }) {
  const words = NEEDS[needs];
  return (
    <button type="button" className="pick" title={words.pick} onClick={askForScope}>
      <span className="name">{name}</span>
      <span className="needs">{words.tag}</span>
    </button>
  );
}

// The address a file comes from. Built here rather than by the generated client
// because it is a link somebody follows rather than a request this page makes
// — the browser fetches it with the session it already has.
function vexAt(product: string, stream: string, variant: string) {
  return (
    `/v1/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}/vex`
  );
}
