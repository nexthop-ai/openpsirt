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
// **The third is the findings list, not a panel here.** A screen that offers
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
          Each answers one question, at whatever the picker above has selected, and prints.
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
          Every other file is offered on the screen that answers for it, narrowed the way that
          screen is narrowed. These two have no screen of their own.
        </p>
        <ul className="files catalog">
          <li>
            <div>
              What is <b>running out of time</b> — <a href="/v1/running-out.csv?days=30">CSV</a> ·{" "}
              <a href="/v1/running-out.json?days=30">JSON</a>
            </div>
            <div className="hint">
              Open, undecided, and due inside the window, across every product you can read. Thirty
              days by default; <span className="id">?days=</span> takes any number up to a year. A
              deadline somebody has answered is not on it: a dismissal takes a finding off the clock
              and a deferral replaces the deadline with its own date, so what is left is time
              passing with nothing said.
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
                What stands about the components that build ships, as a customer&rsquo;s own scanner
                reads it. Approved dismissals only, public findings only, and a deferral is absent
                rather than published as anything.
              </div>
            </li>
          ) : (
            <li>
              <div>
                A <b>VEX document</b>
              </div>
              <div className="hint">
                Pick a product, a branch or tag, and a variant above: what stands about a component
                is a fact about one build, so there is no such document for a selection that spans
                several.
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
              A question with no name is asked where the filters live: narrow it there, look at what
              it catches, and take the whole of it as a file — with or without a product picked.
            </div>
          </li>
        </ul>
      </section>
    </>
  );
}

// Where a file comes from. Built here rather than by the generated client
// because it is a link somebody follows rather than a request this page makes
// — the browser fetches it with the session it already has.
function vexAt(product: string, stream: string, variant: string) {
  return (
    `/v1/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}/vex`
  );
}
