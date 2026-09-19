// The record of the flaw, as against what anybody has said about it.
//
// The component's place, upstream's releases, the route the scanner
// matched it, what the published references say, and who reported it. None of
// it is a judgment; all of it is what somebody reads before making one.

import { Fragment, useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { statusOf, unwrap } from "../api/queries";
import { linkable } from "../ui/addressable";
import { Failed } from "../ui/Failed";
import { UNPLACED, type Sitting } from "../ui/Covering";
import { intoTheTree, wayDown } from "./waydown";

// Every place the component sits at, as the complete chain. A place is the
// component and what directly pulled it in, which is what a decision is
// recorded against.
const CHAINS = 6;

// Away is an address somebody else supplied, shown as a link only where it is
// one this deployment is willing to send a reader to.
//
// A scanner's references and a feed's records are strings from outside, and a
// string in an href is a scheme the browser acts on rather than encoded
// output. What fails the check is still shown — losing the address would lose
// the evidence — it is simply not clickable.
function Away({ url }: { url?: string }) {
  const href = linkable(url);
  if (!href) {
    return <span className="id">{url}</span>;
  }
  return (
    <a href={href} target="_blank" rel="noreferrer noopener">
      {href.replace(/^https?:\/\//, "")}
    </a>
  );
}

export function Places({
  places,
  build,
  version,
}: {
  places: Sitting[];
  build: string;
  // The versions shipped here, for a way down the graph could not walk: the
  // chain carries a version at every step and a place without one carries none.
  version?: string;
}) {
  const [all, setAll] = useState(false);
  if (places.length === 0) return null;
  const shown = all ? places : places.slice(0, CHAINS);
  return (
    <div className="pathblock">
      <h3>Dependency path</h3>
      <div className="tree">
        {shown.map((place, i) => {
          const { steps, rootless } = wayDown(place, version);
          return (
            <Fragment key={`${place.place} ${i}`}>
              {steps.map((step, depth) => {
                const last = depth === steps.length - 1;
                return (
                  <div
                    key={`${place.place} ${i} ${depth}`}
                    className={`node${last ? " here" : ""}`}
                    style={{ paddingLeft: depth * 18 }}
                  >
                    <span className="rule">└</span>
                    <span className="id">{step.component}</span>
                    {step.version && <span className="ver">{step.version}</span>}
                    {/* Said at the top of the way down, which is where it is
                        true: the consumer under it is what the record names,
                        and what pulls *that* in is what nothing recorded. */}
                    {depth === 0 && rootless && <span className="hint">{UNPLACED}</span>}
                    {/* What the producer called this dependency, where it
                        said anything. Shown and read by nothing: it does not
                        rank, does not prefill an outcome, and hides nothing.
                        "Build-time only" is the largest deferral class a
                        vendor has, and it is a person's to make. */}
                    {last && place.declared_as && (
                      <span className="state" title="What the producer called this dependency">
                        producer said {place.declared_as}
                      </span>
                    )}
                    {last && place.suppressed && (
                      <span className="state open">suppressed by the build</span>
                    )}
                    {last && place.decision != null && (
                      <Link to={`/decisions/${place.decision}`} className="linkish">
                        decided
                      </Link>
                    )}
                  </div>
                );
              })}
            </Fragment>
          );
        })}
      </div>
      {places.length > CHAINS && (
        <button type="button" className="linkish" onClick={() => setAll(!all)}>
          {all ? `Show ${CHAINS}` : `Show all ${places.length} ways down`}
        </button>
      )}
      {/* The tree is handed the whole chain, not only the name: it opens
          each step on the way down and lands on the component, so arriving
          from a finding shows where it sits rather than the root.

          From a place the graph could be walked to, whichever of them that
          is. A chain is what the tree opens along, and the first place is not
          always one that has a route up — handed that one, the tree was given
          a name to land on and no way down to it. */}
      <Link to={`${build}/components?${intoTheTree(places)}`} className="linkish">
        View in dependency tree →
      </Link>
    </div>
  );
}

// Patches first: for somebody deciding whether to backport rather than
// upgrade, the change itself is the answer.
export function References({
  advisory,
  refs,
}: {
  advisory?: string;
  refs: { url?: string; kind?: string }[];
}) {
  const all = advisory ? [{ url: advisory, kind: "advisory" }, ...refs] : refs;
  if (all.length === 0) return null;
  const order: Record<string, number> = { patch: 0, advisory: 1, report: 2, other: 3 };
  const sorted = [...all].sort(
    (a, b) => (order[a.kind ?? "other"] ?? 9) - (order[b.kind ?? "other"] ?? 9),
  );
  return (
    <div className="evblock">
      <h4>References</h4>
      <ul className="refs">
        {sorted.slice(0, 12).map((ref) => (
          <li key={ref.url}>
            <span className={ref.kind === "patch" ? "kind patch" : "kind"}>{ref.kind}</span>{" "}
            <Away url={ref.url} />
          </li>
        ))}
      </ul>
      <p className="hint">Patches first.</p>
    </div>
  );
}

// The route the scanner reached this by, which is the first thing anybody asks
// about a distribution's package.
//
// An advisory for the package's own ecosystem counts the release number and
// names the release that carries the fix. An identifier compared against an
// upstream version range cannot see a backported fix at all — the patch does
// not move the upstream version — so it fires whether or not whoever packages
// this has already dealt with it.
//
// The findings list marks these and the screen somebody decides on did not,
// which is the wrong way round: the list is where they are noticed and this is
// where the judgment is made. Nothing is said where the scanner said nothing,
// because unknown is not unconfirmed.
export function HowMatched({
  matched,
  from,
  version,
  inData,
  range,
}: {
  matched?: string;
  from?: string;
  version?: string;
  inData?: string;
  range?: string;
}) {
  if (matched !== "identifier" && matched !== "advisory") return null;
  return (
    <div className="evblock">
      <h4>Match evidence</h4>
      {matched === "identifier" ? (
        <p title="Matched on a version range, not a packager advisory">
          <b>Not confirmed by a packager.</b> May already be fixed in{" "}
          <span className="id">{version}</span>.
        </p>
      ) : (
        <p title="Matched through the package's own advisory">
          <b>Confirmed by a packager.</b>
        </p>
      )}
      {/* The evidence for the judgment above rather than a second way of
          making it: the range fired on, read beside the version that ships.
          Where the range names no packaging revision and the version has one,
          the argument is complete in a line and needs no explaining. */}
      {(range || inData) && (
        <p className="mono" style={{ fontSize: "var(--step--1)" }}>
          {range && (
            <>
              matched <b>{range}</b> against <b>{version}</b>
            </>
          )}
          {range && inData && " · "}
          {inData && <>from {inData}</>}
        </p>
      )}
      {from && (
        <p className="hint" title="Where the match data came from">
          Source <Away url={from} />
        </p>
      )}
    </div>
  );
}

// The places to read about this, worked out from the names held here rather
// than handed over by a scanner.
//
// A scanner points at whatever its data carried, which for a package matched
// by identifier is often another distribution's write-up and need not include
// the issue's own record at all. These resolve because an identifier names a
// record and a package identifier names a package.
export function LookItUp({ links }: { links: { url?: string; name?: string }[] }) {
  if (links.length === 0) return null;
  return (
    <div className="evblock">
      <h4>Issue records</h4>
      <ul className="refs">
        {links.map((link) => (
          <li key={link.url}>
            <span className="kind">{link.name}</span> <Away url={link.url} />
          </li>
        ))}
      </ul>
      <p className="hint">Worked out from the identifiers, not supplied by the scanner.</p>
    </div>
  );
}

// The reporter of a flaw, and the other names it goes by.
//
// The reporter is the party the timeline is evidenced to. Received,
// acknowledged, triaged, fixed, disclosed — and the acknowledgment is the step
// that costs nothing and is missed by being nobody's job, so it is a button
// here rather than a field somebody remembers to fill in.
//
// Acknowledging records that it happened rather than doing it. What
// reaches a researcher is a mail somebody sends from an address they already
// have; recording it turns "somebody probably replied" into a date.
export function WhoTold({ product, vulnerability }: { product: string; vulnerability: string }) {
  const queries = useQueryClient();
  const [alias, setAlias] = useState("");
  const told = useQuery({
    queryKey: ["report", product, vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/report", {
          params: { path: { product, vulnerability } },
        }),
      ),
    // Nobody recorded a reporter, which is every flaw we found ourselves.
    retry: false,
  });
  const answered = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/report/acknowledgement", {
          params: { path: { product, vulnerability } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["report"] }),
  });
  const alsoKnown = useMutation({
    mutationFn: async (name: string) =>
      unwrap(
        await api.PUT("/v1/products/{product}/issues/{vulnerability}/aliases/{alias}", {
          params: { path: { product, vulnerability, alias: name } },
        }),
      ),
    onSuccess: () => {
      setAlias("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const report = told.data;
  return (
    <div className="card">
      <h3>Reported by</h3>
      {told.isPending ? (
        <Loading />
      ) : told.isError && statusOf(told.error) !== 404 ? (
        // 404 alone, not every refusal. This is the one card where the two
        // statuses mean opposite things: the endpoint answers 404 for "nobody
        // recorded a reporter", which is every flaw found in-house, and 403
        // for "you do not hold triage here" — so folding them told a case
        // collaborator the flaw was found in-house, which is a false claim
        // about a security record rather than a quiet card.
        <Failed error={told.error} what="Who reported this could not be read." />
      ) : !report ? (
        <p className="reading">No outside reporter recorded.</p>
      ) : (
        <>
          <p className="reading" style={{ marginBottom: 6 }}>
            <b>{report.reported_by || "Somebody"}</b>
            {report.contact && (
              <>
                {" "}
                · <span className="id">{report.contact}</span>
              </>
            )}
            {report.received && <> · arrived {report.received}</>}
            {report.credit && <> · credited as {report.credit}</>}
          </p>
          {report.acknowledged ? (
            <p className="hint">
              Answered {report.acknowledged.replace("T", " ").slice(0, 16)}
              {report.acknowledged_by && <> by {report.acknowledged_by}</>}.
            </p>
          ) : (
            <div className="alert" style={{ margin: "6px 0 0" }}>
              <strong>Nobody has answered them.</strong>
              <span>Send them a note, then record it here.</span>
              <button
                type="button"
                className="btn"
                style={{ marginLeft: "auto" }}
                disabled={answered.isPending}
                onClick={() => answered.mutate()}
              >
                Mark as answered
              </button>
            </div>
          )}
          {answered.error != null && (
            <Failed error={answered.error} what="That could not be recorded." />
          )}
        </>
      )}

      {/* A CVE assigned later is another name for the same issue.
          Nothing keyed on the issue moves; what changes is that a reader
          searching by the new name finds this, and the advisory carries it. */}
      <div className="field" style={{ marginTop: 12, marginBottom: 0 }}>
        <label htmlFor="also-known">Also known as</label>
        <div style={{ display: "flex", gap: 6 }}>
          <input
            id="also-known"
            type="text"
            value={alias}
            placeholder="CVE-2027-0001"
            onChange={(event) => setAlias(event.target.value)}
          />
          <button
            type="button"
            className="btn quiet"
            disabled={alias.trim() === "" || alsoKnown.isPending}
            onClick={() => alsoKnown.mutate(alias.trim())}
          >
            Record
          </button>
        </div>
        <span className="hint">
          A CVE assigned after we minted our own. Findings and decisions are unaffected.
        </span>
        {alsoKnown.error != null && (
          <Failed error={alsoKnown.error} what="That name could not be recorded." />
        )}
      </div>
    </div>
  );
}
