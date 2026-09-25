// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useScope } from "../../app/scope";
import { CATALOG, leadsTo, scopeWords } from "./catalog";

// The catalog of named reports.
//
// The screen this replaced was a metrics dashboard and an ad-hoc export panel
// stapled together, under a name that promised neither. What somebody means by
// a report is one of three things — a question with a name, a file to send to
// somebody without an account here, or a question nobody had a name for — and
// the screen answered the middle one only by accident.
//
// So: the named ones first, and beneath them the two files that exist nowhere
// else. Each named report is a page of its own, which is what makes it
// printable, linkable and quotable — a section of a dashboard is none of those.
//
// The third is the findings list, not a panel here. A screen that offers
// the findings list's filters and the findings list's query is the findings
// list at a second address, and the copy is always the poorer one: it offered
// fewer filters than the screen it copied. What it did that the list did not
// was export without a product picked, which was a gap in the list.
export function Catalog() {
  const at = useScope();

  return (
    <>
      <div className="screen-head">
        <h2>Reports</h2>
        <p>{scopeWords(at)} — named reports, and the two files that live nowhere else.</p>
      </div>

      <section className="panel">
        <h3>Named reports</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Each answers one question, at the selection above.
        </p>
        <ul className="files catalog">
          {CATALOG.map((report) => {
            const { to, why } = leadsTo(report, at);
            return (
              <li key={report.slug ?? report.name}>
                <div>{to ? <Link to={to}>{report.name}</Link> : <b>{report.name}</b>}</div>
                <div className="hint">
                  {report.answers}
                  {/* A report that cannot answer yet is still listed, saying
                      what to pick. Dropping it from the list would read as a
                      report that does not exist. */}
                  {why ? ` ${why}` : ""}
                </div>
              </li>
            );
          })}
        </ul>
      </section>

      {/* Only what is reachable nowhere else. The record of judgments, the
          review queue, the by-component view, the comparison and the register
          are all files offered on the screen that produces them, and those
          copies are the better ones because they carry that screen's filters
          — the links here were unfiltered. */}
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
              <div>
                A <b>VEX document</b>
              </div>
              <div className="hint">
                Pick a product, a branch or tag, and a variant above. This document is per build.
              </div>
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
