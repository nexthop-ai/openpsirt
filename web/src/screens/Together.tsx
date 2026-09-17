import { notACredential } from "../ui/noautofill";
import { Icon } from "../ui/Icons";
import { useMemo, useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { paths } from "../api/schema";
import { usePaging } from "./list";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Crumbs } from "../ui/Crumbs";
import { Severity, Exploited } from "../ui/Severity";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { JUSTIFICATIONS, type Justification } from "../ui/Outcome";
import { Editor, forget } from "../ui/Editor";
import { Paged } from "../ui/Paged";

// A page of issues at one component. A kernel carries thousands, and a list
// drawn as if it were all of them says "select all" against a number that is
// not the whole.
const PAGE = 500;

// The body this screen sends, by the name the API document gives it. Taken
// from the generated client rather than restated, so a field the server
// requires cannot be left out of the call and noticed by nobody.
type Claimed = NonNullable<
  paths["/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/decisions"]["post"]["requestBody"]
>["content"]["application/json"];

// One judgment about many issues at one component. The transpose of the usual
// grouping: one issue across many places is what a decision already covers,
// and a kernel carrying thousands of issues — most of them in drivers a given
// image never builds — has no answer at all without this.
//
// The claim is ordinary and needs a second person like any other dismissal.
// What makes it defensible is that it writes a separate decision per issue and
// per place, each keyed and expiring on its own, rather than one blanket claim.
export function Together() {
  const { product = "", stream = "", variant = "", component = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const contains = params.get("contains") ?? "";
  const { offset, go } = usePaging();
  const [typed, setTyped] = useState(contains);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const queries = useQueryClient();

  const at = { product, stream, variant, component };
  // The whole build, not the product and the component. Keyed on two of the
  // four, the same component under two variants shared one draft and each
  // cleared the other's — and what is kept here is the reasoning a second
  // person is asked to agree to.
  const draftKey = `together:${product}:${stream}:${variant}:${component}`;

  const issues = useQuery({
    queryKey: ["at-component", at, contains, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/issues",
          {
            params: { path: at, query: { limit: PAGE, offset, ...(contains ? { contains } : {}) } },
          },
        ),
      ),
  });

  const decide = useMutation({
    // The body the generated client declares, so the two fields the server
    // requires for a deferral and an already-fixed claim are checked here
    // rather than refused there. Cast to `never`, the form could send a claim
    // missing either and nothing in this file would notice.
    mutationFn: async (body: Claimed) =>
      unwrap(
        await api.POST(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/decisions",
          { params: { path: at }, body },
        ),
      ),
    onSuccess: () => {
      // Cleared only once the server has taken it. A refused submission keeps
      // every word, which is the whole point of keeping a draft at all.
      forget(draftKey);
      setPicked(new Set());
      void queries.invalidateQueries({ queryKey: ["at-component"] });
      void queries.invalidateQueries({ queryKey: ["queue"] });
    },
  });

  // Memoized because the fallback is a fresh array each render, and the page
  // is what the reach map below merges from: an array that changes identity
  // every render would merge on every render.
  const items = useMemo(() => issues.data?.items ?? [], [issues.data]);
  const everything = issues.data?.total ?? items.length;
  const cap = issues.data?.cap ?? 0;

  // How far the selection reaches, in rows written rather than issues picked.
  //
  // The selection spans pages and a page does not, so this remembers every row
  // it has seen rather than summing the page in hand: a selection made across
  // two pages counted only the second and understated the write, which is the
  // figure the over-cap warning is read off.
  //
  // A name it has still never seen came from "select all matching", which
  // answers with names alone — so that case falls back to the server's own
  // count of the whole narrowed set rather than to zero.
  const [reach, setReach] = useState(() => new Map<string, number>());
  const [merged, setMerged] = useState(items);
  if (merged !== items) {
    setMerged(items);
    const next = new Map(reach);
    for (const each of items) next.set(each.vulnerability ?? "", each.places ?? 0);
    setReach(next);
  }
  const everySelected = picked.size > 0 && picked.size === everything;
  const unseen = [...picked].some((name) => !reach.has(name));
  const writing =
    everySelected || unseen
      ? (issues.data?.findings ?? 0)
      : [...picked].reduce((sum, name) => sum + (reach.get(name) ?? 0), 0);
  const over = cap > 0 && writing > cap;

  // Everything the filter matches, not everything on the page. Fetched in one
  // request at the largest page the server offers, and repeated until the set
  // is complete, because a selection assembled a page at a time is a claim
  // somebody meant to make once.
  const all = useQuery({
    enabled: false,
    queryKey: ["at-component-all", at, contains],
    queryFn: async () => {
      const names: string[] = [];
      for (let from = 0; from < everything; from += 500) {
        const page = unwrap(
          await api.GET(
            "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/issues",
            {
              params: {
                path: at,
                query: { limit: 500, offset: from, ...(contains ? { contains } : {}) },
              },
            },
          ),
        );
        for (const each of page.items ?? []) names.push(each.vulnerability ?? "");
        if ((page.items ?? []).length === 0) break;
      }
      return names;
    },
  });

  async function selectEverything() {
    const got = await all.refetch();
    if (got.data) setPicked(new Set(got.data));
  }

  return (
    <>
      <Crumbs product={product} stream={stream} variant={variant} />
      <div className="screen-head">
        <h2>Bulk decision</h2>
        <p>
          <span className="id">{component}</span> · {product} · {stream} · {variant} — one outcome,
          one reasoning, a separate record per issue and per place. Nothing here selects for you.
        </p>
      </div>

      <div className="filters">
        <form
          className="searchbox"
          onSubmit={(event) => {
            event.preventDefault();
            // A selection is made out of a population, so replacing the
            // population replaces what was selected. Kept across a narrowing,
            // issues ticked under the old question were submitted under the
            // new one, with none of them on screen.
            setPicked(new Set());
            setParams(typed ? { contains: typed } : {});
          }}
        >
          <Icon name="search" />
          <input
            {...notACredential}
            type="text"
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
            placeholder="Narrow by what the report says — driver, ioctl…"
            aria-label="Narrow the list"
          />
        </form>
        <span className="hint">Text match on the description</span>
      </div>

      {issues.isPending && <Loading />}
      {issues.isError && <Failed error={issues.error} what="The issues could not be read." />}

      {issues.data && items.length === 0 && (
        <Empty
          title="Nothing matches."
          detail="Nothing is open against this component under that narrowing."
        />
      )}

      {items.length > 0 && (
        <>
          <div className="batchbar" style={{ marginBottom: 8 }}>
            <span>
              <b>
                {picked.size.toLocaleString()} of {everything.toLocaleString()} selected
              </b>
            </span>
            <button
              type="button"
              className="linkish"
              onClick={() => setPicked(new Set(items.map((i) => i.vulnerability ?? "")))}
            >
              Select all {items.length.toLocaleString()} shown
            </button>
            {/* The whole narrowed set, not the page. A page is fifty of eight
                hundred, and a claim assembled a page at a time is eighteen
                claims where the person meant one. */}
            {everything > items.length && (
              <button
                type="button"
                className="linkish"
                disabled={all.isFetching}
                onClick={() => void selectEverything()}
              >
                {all.isFetching
                  ? "Selecting…"
                  : `Select all ${everything.toLocaleString()} matching`}
              </button>
            )}
            <span className="spacer" />
            <button type="button" className="linkish" onClick={() => setPicked(new Set())}>
              Clear
            </button>
          </div>

          {/* What it would write, said before anybody types a reasoning. The
              bound is on findings and the list counts issues, so a screen that
              said only the second reports 44 where the answer is 2,000. */}
          {picked.size > 0 && (
            <p className={over ? "alert warn" : "hint"} style={{ margin: "0 0 10px" }}>
              {picked.size.toLocaleString()} {picked.size === 1 ? "issue" : "issues"} ·{" "}
              <b>{writing.toLocaleString()}</b> {writing === 1 ? "finding" : "findings"} would be
              written
              {cap > 0 && <> · the limit here is {cap.toLocaleString()}</>}
              {over && (
                <>
                  {" "}
                  — narrow the selection, or raise the limit deliberately. An issue sits at more
                  than one place, so a short list can still be a long write.
                </>
              )}
            </p>
          )}

          {/* The evidence one judgment is being made on. It showed the
              identifier, the severity and a place count and nothing else —
              while narrowing by the description, which it did not show. One
              click here writes a claim across hundreds of places, so it says
              at least as much as the screen for deciding one. */}
          <div className="picklist">
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 34 }}>
                      <input
                        type="checkbox"
                        aria-label="Select every row shown"
                        checked={
                          items.length > 0 && items.every((i) => picked.has(i.vulnerability ?? ""))
                        }
                        onChange={(event) => {
                          const next = new Set(picked);
                          for (const issue of items) {
                            if (event.target.checked) next.add(issue.vulnerability ?? "");
                            else next.delete(issue.vulnerability ?? "");
                          }
                          setPicked(next);
                        }}
                      />
                    </th>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th className="num" title="EPSS: published probability of exploitation">
                      EPSS
                    </th>
                    <th>Fixed in</th>
                    <th className="num">Places</th>
                    <th>Due</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((issue) => {
                    const name = issue.vulnerability ?? "";
                    return (
                      <tr key={name} className="row">
                        <td>
                          <input
                            type="checkbox"
                            aria-label={`Select ${name}`}
                            checked={picked.has(name)}
                            onChange={(event) => {
                              const next = new Set(picked);
                              if (event.target.checked) next.add(name);
                              else next.delete(name);
                              setPicked(next);
                            }}
                          />
                        </td>
                        <td>
                          <Severity word={issue.severity} />
                        </td>
                        <td>
                          <Link to={`/issues/${encodeURIComponent(name)}`} className="id">
                            {name}
                          </Link>{" "}
                          <Exploited when={issue.exploited} />
                          {/* What the issue says about itself. The screen
                              narrows on this text and showed none of it, so a
                              term matched rows nobody could check. */}
                          {issue.summary && <div className="hint">{issue.summary}</div>}
                        </td>
                        <td className="num">
                          {typeof issue.likelihood === "number" && issue.likelihood > 0
                            ? issue.likelihood.toFixed(2)
                            : ""}
                        </td>
                        <td>
                          {issue.fixed_in ? <span className="id">{issue.fixed_in}</span> : ""}
                        </td>
                        <td className="num">{issue.places}</td>
                        <td>{issue.due ? on(issue.due) : <span className="hint">none</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Wide>
          </div>
          <Paged
            shown={items.length}
            total={issues.data?.total}
            offset={offset}
            limit={PAGE}
            onGo={go}
          />

          <Claim
            narrowed={contains}
            count={picked.size}
            onClaim={(body) => decide.mutate({ ...body, vulnerabilities: [...picked] })}
            pending={decide.isPending}
            error={decide.error}
            recorded={decide.data?.recorded}
            draftKey={draftKey}
            mentions={{ product }}
          />
        </>
      )}
    </>
  );
}

function Claim({
  narrowed,
  count,
  onClaim,
  pending,
  error,
  recorded,
  draftKey,
  mentions,
}: {
  narrowed: string;
  count: number;
  onClaim: (body: Omit<Claimed, "vulnerabilities">) => void;
  pending: boolean;
  error: unknown;
  recorded?: number;
  draftKey: string;
  mentions: { product: string };
}) {
  // Typed against the closed vocabulary the server declares, so a word the
  // form offers that the server does not take is a compile error rather than
  // a refusal somebody reads after pressing submit.
  const [outcome, setOutcome] = useState<Claimed["outcome"]>("not-applicable");
  const [justification, setJustification] = useState<Justification>(JUSTIFICATIONS[0].value);
  // Prefilled from the narrowing that is on, in the form the approver's
  // outlier check reads back — `contains "driver"` — and still editable, since
  // how a set was chosen may be more than one term.
  const [selectedBy, setSelectedBy] = useState(narrowed ? `contains "${narrowed}"` : "");
  const [until, setUntil] = useState("");
  const [fixedVersion, setFixedVersion] = useState("");
  const [reasoning, setReasoning] = useState("");

  const needsJustification = outcome === "not-applicable";
  // What the two bulk outcomes need beside a reasoning. Asked for here rather
  // than discovered as a refusal after the reasoning is typed.
  const needsDate = outcome === "deferred";
  const needsVersion = outcome === "already-fixed";
  const ready =
    count > 0 &&
    reasoning.trim() !== "" &&
    selectedBy.trim() !== "" &&
    (!needsDate || until !== "") &&
    (!needsVersion || fixedVersion.trim() !== "");

  return (
    <section className="card act">
      <h3>
        Decision for {count.toLocaleString()} {count === 1 ? "issue" : "issues"}
      </h3>

      <div className="fields">
        <label className="field">
          <span className="l">Outcome</span>
          <select
            value={outcome}
            onChange={(event) => setOutcome(event.target.value as Claimed["outcome"])}
          >
            <option value="not-applicable">Not applicable</option>
            <option value="wont-fix">Will not fix</option>
            <option value="affected">Affected</option>
            {/* The two bulk cases that were missing: a bump scheduled for the
                next release, and a distribution's backport. */}
            <option value="deferred">Deferred</option>
            <option value="already-fixed">Already fixed</option>
          </select>
        </label>

        {needsDate && (
          <label className="field">
            <span className="l">Returns on</span>
            <input type="date" value={until} onChange={(event) => setUntil(event.target.value)} />
          </label>
        )}

        {needsVersion && (
          <label className="field">
            <span className="l">Fixed in</span>
            <input
              {...notACredential}
              type="text"
              value={fixedVersion}
              onChange={(event) => setFixedVersion(event.target.value)}
              placeholder="the package version the fix arrived in, as the packager writes it"
            />
            <span className="hint">
              One version for every issue here. If they differ, this is not one claim.
            </span>
          </label>
        )}

        {needsJustification && (
          <label className="field">
            <span className="l">Justification</span>
            <select
              value={justification}
              // The options are the vocabulary, so what comes back is one of
              // it. The type is read out of that list now rather than written
              // beside it.
              onChange={(event) => setJustification(event.target.value as Justification)}
            >
              {JUSTIFICATIONS.map((each) => (
                <option key={each.value} value={each.value} title={each.value}>
                  {each.label} — {each.means}
                </option>
              ))}
            </select>
          </label>
        )}

        {/* Recorded with every claim, separately from the reasoning. How a
            candidate was found is not why the claim is true — "these matched a
            word" is not a defense anybody would accept — but "how were these
            chosen" is the question asked of a bulk judgment months later. */}
        <label className="field">
          <span className="l">Narrowed by</span>
          <input
            {...notACredential}
            type="text"
            value={selectedBy}
            onChange={(event) => setSelectedBy(event.target.value)}
            placeholder="e.g. searched the reports for the drivers this image does not build"
          />
        </label>

        {/* No attach control here, deliberately. One judgment covers many
            issues, and a file hangs off one — so there is nothing this could
            attach to that would be true of the rest. */}
        <div className="field">
          <span className="l">Reasoning</span>
          <Editor
            value={reasoning}
            onChange={setReasoning}
            draftKey={draftKey}
            label="Reasoning"
            mentions={mentions}
            placeholder="What makes this true of all of them? A search term is not a reason."
          />
        </div>

        {error != null && <Failed error={error} what="That could not be recorded." />}
        {typeof recorded === "number" && recorded > 0 && (
          <p className="alert info" role="status">
            <strong>{recorded.toLocaleString()} records written — one per issue, per place.</strong>
            <span>One claim, pending a second person; each record expires on its own.</span>
          </p>
        )}

        <div>
          <button
            type="button"
            disabled={!ready || pending}
            onClick={() => {
              onClaim({
                outcome,
                ...(needsJustification ? { justification } : {}),
                ...(needsDate ? { deferred_until: until } : {}),
                ...(needsVersion ? { fixed_version: fixedVersion.trim() } : {}),
                selected_by: selectedBy,
                // The narrowing itself, beside the sentence about it. The
                // server re-runs it and records what it reaches against what
                // was named, so an approver has something to check rather
                // than only something to read.
                ...(narrowed ? { contains: narrowed } : {}),
                reasoning,
              });
            }}
            className="btn"
          >
            Submit for {count.toLocaleString()}
          </button>{" "}
          <span className="hint">Always needs a second person, whatever the outcome.</span>
        </div>
      </div>
    </section>
  );
}
