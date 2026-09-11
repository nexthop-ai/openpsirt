import { decidedAs } from "../ui/decided";
import { notACredential } from "../ui/noautofill";
import { ByBump, ByComponent, Pager, Peek, Sits } from "./FindingsViews";
import { FLOORS } from "../ui/severities";
import { Filters, Narrowed, STATES, activeFilters, without, withoutAny } from "./FindingsFilters";
import { Choices } from "../ui/Choices";
import { Fragment, useMemo, useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Exploited, Severity } from "../ui/Severity";
import { Icon } from "../ui/Icons";
import { Holder } from "../ui/Holder";
import { Saved, type Prepared } from "../ui/Saved";
import { said } from "../ui/Decide";
import { useWho } from "../app/session";
// The page sizes, the orders, the filters and where a row goes all live beside
// the list rather than in it, because the finding screen asks the same
// question of the server to offer the row before and the row after. Fifty rows
// is 153 pages of one product's findings, which is not a list anybody
// assembles a day's work out of.
import {
  PAGE,
  PAGES,
  SORTS,
  acrossProducts,
  asAsked,
  hiddenIn,
  identityOf,
  listQuery,
  pageSize,
  pathTo,
  type Row,
  usePaging,
} from "./list";

// The filters the by-bump view can apply, by the key their chip carries.
//
// Six of the thirty-odd. The rest ask about a place, a deadline or an
// assignee, and a bump has none of those — so they are named on that screen
// rather than dropped, which is what would widen the list back out while the
// chips went on saying they were on.
const BUMPABLE = new Set(["q", "floor", "exploited", "component", "ecosystem", "state"]);

// How long this has been open here.
//
// The finding's own age, not the year in the identifier: an issue assigned in
// 2019 that first appeared in this product last week has been somebody's
// problem for a week, and the identifier already carries its own year for
// anybody who wants it. This is also the age a deadline relates to.
function openFor(opened: string | undefined): string | null {
  if (!opened) return null;
  const days = Math.floor((Date.now() - Date.parse(opened + "T00:00:00Z")) / 86_400_000);
  if (!Number.isFinite(days) || days < 0) return null;
  if (days < 60) return `open ${days}d`;
  if (days < 730) return `open ${Math.floor(days / 30)}mo`;
  return `open ${Math.floor(days / 365)}y`;
}

// What to say in the Due column, and how to color it.
//
// A blank cell would mean two deliberate things at once — below the line or
// past end of life — on the one screen whose purpose is noticing what is
// running out, so the reason is said.
function dueSays(row: { due?: string; days_left?: number; no_deadline?: string }): {
  text: string;
  tone: "over" | "soon" | "fine" | "none";
} {
  if (!row.due) {
    return {
      text: row.no_deadline === "out-of-support" ? "out of support" : "below the line",
      tone: "none",
    };
  }
  const left = row.days_left ?? 0;
  if (left < 0) return { text: `${-left}d over`, tone: "over" };
  if (left <= 7) return { text: `${left}d left`, tone: "soon" };
  return { text: row.due, tone: "fine" };
}

// What upstream has done, said rather than left to be inferred from a blank.
function upstreamSays(state: string | undefined, fixedIn: string | undefined) {
  if (fixedIn) return { text: fixedIn, kind: "id" as const };
  switch (state) {
    case "wont-fix":
      return { text: "declined", kind: "note" as const };
    case "none":
      return { text: "none yet", kind: "note" as const };
    default:
      return { text: "—", kind: "faint" as const };
  }
}

// One row per issue in a component, not per place. Every filter is in the URL,
// so a link carries what somebody is looking at; every filter is the server's,
// so the total beside the list counts the same thing the list shows.
//
// Deciding is not done from here (deciding on the finding's own screen,
// reversed). A row previews in place — the description and where the component
// sits — and opens the finding, which is where a judgment is made with the
// evidence beside it.
export function Findings() {
  const { product = "", stream: named = "", variant: builtAs = "" } = useParams();
  // No product in the path means every product the reader may see. The server
  // has taken the same filters for both lists from the start — one struct,
  // embedded in each — so what differed was only ever the screen.
  const spanning = product === "";
  const [params, setParams] = useSearchParams();
  // The branch and the variant come from the path on a build's own list and
  // from the picker's selection otherwise. Either may be "all": the list is
  // not one of the screens that needs a whole build.
  const stream = named || params.get("stream") || "";
  const variant = builtAs || params.get("variant") || "";
  const oneBuild = Boolean(stream && variant);
  // What the server needs to know about the selection, beside the filters.
  //
  // Held rather than rebuilt each render, so the memo below it does not
  // recompute every time — and so the interface's own lint count stays the
  // honest measure the config says it is: nine warnings of one pattern, and
  // not a tenth of another nobody had accounted for.
  const selection = useMemo(
    () => ({ ...(stream ? { stream } : {}), ...(variant ? { variant } : {}) }),
    [stream, variant],
  );
  const navigate = useNavigate();
  const { offset, go } = usePaging();
  const page = pageSize(params);
  const sort = params.get("sort") ?? "";
  const ascending = params.get("asc") === "yes";
  const floor = params.get("floor") ?? "low";
  const view = params.get("view") ?? "issues";
  const hiding = hiddenIn(params);
  const below = params.get("below") === "yes";
  const searching = params.get("q") ?? "";
  // Everything under a node of the dependency tree, by the tree's own walk,
  // so the tree's count and this list agree. Read here because the notice
  // above the list names it; the query it narrows is built elsewhere.
  const beneath = params.get("beneath") ?? "";
  // Everything else the list narrows by is read where the panel draws it. It
  // used to be pulled apart here, one variable per filter, and every one of
  // them had to be threaded through to the control that set it — which is how
  // the count of what was on came to be a hand-kept list that had already
  // fallen behind the filters it counted. How many filters are on, counted
  // where they are named. It was a list of variables kept in step by hand, and
  // it was already out of step: the count omitted the component name, the
  // subtree, the exclusions and the text search, so a list narrowed by those
  // said it was narrowed by nothing. The address as the list actually reads
  // it, which is not quite what the address says: the by-issue view leaves out
  // what a promised upgrade already answers unless told otherwise. Everything
  // downstream — the query, the chips, the panel, what a row hands the finding
  // it opens — reads this rather than the raw parameters, so the default is
  // visible, removable and travels with a link like any other filter.
  const asked = useMemo(() => asAsked(params, view), [params, view]);
  const advanced = activeFilters(asked).length;
  // Opened because the reader narrowed something, which is not the same as
  // the list being narrowed: the by-issue default would otherwise open the
  // panel on every visit, saying "there is something to look at here" about
  // the one filter nobody set.
  const [more, setMore] = useState(activeFilters(params).length > 0);
  const [peeking, setPeeking] = useState<string | null>(null);
  // What is selected, by what a row *is* rather than by where it sits: the
  // list is read again after every decision and after every page, and an index
  // would select a different row each time. Selection is a prerequisite rather
  // than a convenience — both bulk workflows start by picking a filtered set
  // out of this list.
  //
  // The row travels with the key, not just the key: a selection spans pages by
  // design, and handing one over needs what each row *is* rather than only
  // that it was chosen. Keeping keys alone meant the act could only reach the
  // rows still on screen, so picking thirty on one page and twenty on the next
  // and pressing "Assign 50" wrote twenty and dropped thirty, silently.
  const [picked, setPicked] = useState<Map<string, Row>>(new Map());
  const [handing, setHanding] = useState("");
  // How many of a hand-over did not land. Said rather than swallowed: the loop
  // writes one row at a time, so a failure partway through leaves part of a
  // selection handed over, and the rows that failed stay picked.
  const [handFailed, setHandFailed] = useState(0);
  // What a saved filter prepares, where the one that was picked prepares
  // anything. Offered into the decision form and never applied: a named person
  // submits the claim as their own.
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [typed, setTyped] = useState(searching);
  // A column header that orders by itself. Clicking the one already sorted
  // turns it around; clicking another sorts by that, most-first, because that
  // is what somebody means by "sort by severity".
  function sortable(label: keyof typeof SORTS) {
    const key = SORTS[label];
    const on = sort === key;
    return (
      <button
        type="button"
        className="linkish"
        title={`Order by ${label.toLowerCase()}`}
        onClick={() => {
          const next = new URLSearchParams(params);
          if (on && !ascending) next.set("asc", "yes");
          else {
            next.set("sort", key);
            next.delete("asc");
          }
          asking(next);
        }}
      >
        {label}
        {on && <span aria-hidden> {ascending ? "\u2191" : "\u2193"}</span>}
      </button>
    );
  }

  // Built from the address rather than from the values read out of it, so that
  // the finding screen can build the same query from the same address and
  // there is one place a filter is translated.
  const query = useMemo(() => listQuery(asked), [asked]);

  // The same question as a file: every filter the list asked, and never the
  // paging, since a file is the whole of a narrowing rather than the page in
  // front of somebody. The two lists are two endpoints, and the spanning one
  // drops the filters a single build resolves, so the query is narrowed the
  // same way the screen's own read narrows it.
  const asFile = useMemo(() => {
    const carried = Object.entries(spanning ? acrossProducts(query) : { ...query, ...selection })
      .filter(([key]) => key !== "limit" && key !== "offset")
      .flatMap(([key, value]) =>
        Array.isArray(value) ? value.map((each) => [key, String(each)]) : [[key, String(value)]],
      ) as [string, string][];
    return new URLSearchParams(carried).toString();
  }, [query, selection, spanning]);

  const exportsAt = spanning
    ? "/v1/findings"
    : `/v1/products/${encodeURIComponent(product)}/findings`;

  // What a row hands the finding it opens: the list's own address, with the
  // build it is looking at written in, so the finding can ask for the row
  // before and the row after under exactly these filters.
  const carrying = useMemo(() => {
    const now = new URLSearchParams(asked);
    if (stream) now.set("stream", stream);
    if (variant) now.set("variant", variant);
    return now.toString();
  }, [asked, stream, variant]);

  const queries = useQueryClient();
  // What one action may write here, as the deployment sets it. A selection is
  // handed over a row at a time, so this is the bound on how many round trips
  // one click makes. Read up here with the other hooks, because the screen
  // returns early for two of its views.
  const bulkCap = useWho().data?.bulk_cap ?? 0;
  // What people have marked findings with here, for the filter to offer. Read
  // only while the panel that uses it is open: it is a per-product list nobody
  // needs unless they are narrowing by one.
  const inUse = useQuery({
    enabled: more && !spanning,
    queryKey: ["tags", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/tags", { params: { path: { product } } })),
    retry: false,
  });
  const hand = useMutation({
    mutationFn: async (to: { row: Row; who: string; team: boolean }) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/assignment",
          {
            params: {
              path: {
                ...buildOf(to.row),
                vulnerability: to.row.vulnerability ?? "",
                component: to.row.component ?? "",
              },
            },
            body: to.team ? { team: to.who } : { person: to.who },
          },
        ),
      ),
    // Nothing is invalidated per row. Handing over a selection is a loop of
    // these, and invalidating on each one interleaved a list refetch between
    // every write — so the page spent a long selection refetching rather than
    // writing. The loop invalidates once when it is done.
  });

  const findings = useQuery({
    queryKey: ["findings", product, stream, variant, query],
    queryFn: async () =>
      unwrap(
        spanning
          ? await api.GET("/v1/findings", { params: { query: acrossProducts(query) } })
          : await api.GET("/v1/products/{product}/findings", {
              params: { path: { product }, query: { ...query, ...selection } },
            }),
      ),
    enabled: view === "issues",
  });

  // How many rows sit below what this product triages, and where that line is.
  // A product's own answer: across products each has its own line, so there is
  // no single count to give and no single value to name, and the notice is not
  // drawn. The cross-product response does not carry the two fields at all,
  // which is what makes reading them through a narrowing here rather than off
  // the response the honest form.
  const line = spanning
    ? { hidden: 0, floor: "" }
    : ((findings.data ?? {}) as { hidden?: number; floor?: string });

  // Which build a row's actions and links are about. Where the selection is
  // one build that is the selection; across several the row names one of them
  // and says how many hold it, so the action lands somewhere real and the
  // decision reaches the rest by matching.
  function buildOf(row: Row) {
    return {
      product: row.product || product,
      stream: row.stream || stream,
      variant: row.variant || variant,
    };
  }

  // Every change to the question the list is asking goes through here, which
  // is what makes clearing the selection one line rather than four.
  //
  // **A selection is made out of a population**, so replacing the population
  // replaces what was selected: a triager filtering to low, ticking thirty
  // rows and then clicking critical had a bar still saying thirty while four
  // rows were listed — and handing them over wrote assignments for
  // twenty-six rows nobody could see. The saved-filter path already said this
  // and cleared; nothing else did.
  function asking(next: URLSearchParams) {
    next.delete("offset");
    setPicked(new Map());
    setHandFailed(0);
    setParams(next);
  }

  function set(key: string, value: string) {
    const next = new URLSearchParams(asked);
    if (value) next.set(key, value);
    else next.delete(key);
    asking(next);
  }

  // Several values of one filter, which the address carries as the parameter
  // repeated. Written whole rather than added to, so unticking the last one
  // leaves no empty parameter behind.
  function setMany(key: string, values: string[]) {
    const next = new URLSearchParams(asked);
    next.delete(key);
    for (const value of values) next.append(key, value);
    asking(next);
  }

  function hide(component: string) {
    setMany("hide", [...new Set([...hiding, component])]);
  }

  // Memoized because the fallback is a fresh array each render, which made
  // the effect that lands the cursor depend on something that always changed.
  const rows = useMemo(() => findings.data?.items ?? [], [findings.data]);

  // How many other rows on this page are the same issue at another binary of
  // the same source package. Counted over the page rather than the list,
  // because a page is what somebody is reading and the server counts places —
  // saying otherwise would be a number that disagrees with the total beside
  // it.
  const siblings = useMemo(() => {
    const seen = new Map<string, number>();
    for (const row of rows) {
      if (!row.source || row.source === row.component) continue;
      const key = `${row.vulnerability} ${row.source}`;
      seen.set(key, (seen.get(key) ?? 0) + 1);
    }
    // What is reported is the count of *others*, so a source package with one
    // binary on the page says nothing at all.
    for (const [key, count] of seen) {
      if (count <= 1) seen.delete(key);
      else seen.set(key, count - 1);
    }
    return seen;
  }, [rows]);
  const total = findings.data?.total ?? 0;

  const controls = (
    <>
      <div className="filters">
        <form
          className="searchbox"
          onSubmit={(event) => {
            event.preventDefault();
            set("q", typed.trim());
          }}
        >
          <Icon name="search" />
          <input
            {...notACredential}
            type="text"
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
            placeholder="Find a component — openssl, linux, python…"
            aria-label="Find a component"
          />
        </form>
        {searching && (
          <button
            type="button"
            className="linkish"
            onClick={() => {
              setTyped("");
              set("q", "");
            }}
          >
            Clear “{searching}”
          </button>
        )}
        <span className="seg">
          {[
            ["issues", "By issue"],
            ["components", "By component"],
            ["bumps", "By bump"],
          ].map(([value, label]) => (
            <button
              key={value}
              type="button"
              aria-pressed={view === value}
              onClick={() => set("view", value === "issues" ? "" : (value as string))}
            >
              {label}
            </button>
          ))}
        </span>
        {/* Where somebody starts. The two chips that stood here were
            "exploited" and "fix available", and neither earned the place: the
            list is ordered by urgency, so what is being exploited is already
            at the top of it, and both are still in the panel. What people
            reach for first is what has not been answered yet, and that is a
            question about several states at once — undecided and pending
            approval together are everything nobody has finished with. */}
        <span className="floor">
          <span style={{ color: "var(--faint)" }}>Decision</span>
          <Choices
            bare
            label="Decision state"
            options={STATES}
            chosen={asked.getAll("state").filter(Boolean)}
            onChange={(chosen) => setMany("state", chosen)}
          />
        </span>
        {/* Behind a control rather than always on screen: the chips above are
            what somebody uses constantly. What is on is said on the control,
            so a narrowed list never looks like an unnarrowed one. */}
        <button
          type="button"
          className="chip"
          aria-pressed={advanced > 0 || more}
          aria-expanded={more}
          onClick={() => setMore(!more)}
        >
          Filters{advanced > 0 ? ` · ${advanced}` : ""}
        </button>
        {/* Picking a saved filter replaces what is on screen, so it replaces
          the population a selection was made out of. Keeping the selection
          across that would carry rows chosen under one question into an act
          taken under another, and the bar would go on saying they are
          selected while none of them is listed. */}
        {!spanning && (
          <Saved
            product={product}
            onPrepared={(what) => {
              setPrepared(what);
              setPicked(new Map());
              setHandFailed(0);
            }}
          />
        )}
        <span className="floor">
          <span style={{ color: "var(--faint)" }}>Min severity</span>
          <span className="seg">
            {FLOORS.map((band) => (
              <button
                key={band}
                type="button"
                aria-pressed={floor === band}
                onClick={() => set("floor", band)}
              >
                {band[0]?.toUpperCase()}
                {band.slice(1)}
              </button>
            ))}
          </span>
        </span>
      </div>

      {/* What is narrowing the list, whether or not the panel is open, and
          removable one at a time. The count on the Filters control said how
          many there were and never which, so reading a list somebody sent
          meant opening a panel and looking at nine controls. */}
      <Narrowed
        params={asked}
        clear={(chip) => {
          const next = without(asked, chip);
          next.delete("offset");
          setParams(next);
        }}
        clearAll={() => {
          const next = withoutAny(asked);
          next.delete("offset");
          setParams(next);
        }}
      />

      {more && (
        <Filters
          params={asked}
          set={set}
          setMany={setMany}
          tags={inUse.data?.items ?? []}
          oneBuild={oneBuild}
          spanning={spanning}
        />
      )}

      {/* What the picked filter prepares. Said before anything is
          decided, because what it fills in is what somebody is about to put
          their name to. */}
      {prepared && (
        <div className="alert info" style={{ margin: "10px 0" }}>
          <strong>This filter prepares a claim</strong>
          <span>
            The decision form opens saying <b>{said(prepared.outcome ?? "")}</b> in the words the
            filter carries. Nothing is proposed until you submit it, and it goes out as <b>your</b>{" "}
            claim for a second person to agree to.
          </span>
          <button
            type="button"
            className="linkish"
            style={{ marginLeft: "auto" }}
            onClick={() => setPrepared(null)}
          >
            Do not use it
          </button>
        </div>
      )}

      {beneath && (
        <div className="filters" style={{ marginTop: -4 }}>
          <span style={{ color: "var(--faint)" }}>Beneath</span>
          <button
            type="button"
            className="chip"
            aria-pressed
            title="Show the whole build again"
            onClick={() => set("beneath", "")}
          >
            {beneath} ×
          </button>
          <span className="hint">
            This component and everything under it in the dependency tree.
          </span>
        </div>
      )}
    </>
  );

  if (view === "bumps") {
    return (
      <>
        <div className="screen-head">
          <h2>Findings</h2>
          <p>
            {product} · {stream || "every branch"} · {variant || "every variant"} — one row per
            upstream bump, so you can see what one upgrade would clear before deciding what to read.
          </p>
        </div>
        {controls}
        <ByBump
          at={{ product, stream, variant }}
          query={query}
          offset={offset}
          size={page}
          // A bump has no place, no deadline and no assignee, so the filters
          // that ask about one have no row here to narrow. Named on screen
          // rather than dropped quietly.
          cannot={activeFilters(asked)
            .filter((each) => !BUMPABLE.has(each.key))
            .map((each) => each.label)}
          onPage={(next) => {
            const now = new URLSearchParams(params);
            if (next === 0) now.delete("offset");
            else now.set("offset", String(next));
            setParams(now);
          }}
        />
      </>
    );
  }

  if (view === "components") {
    return (
      <>
        <div className="screen-head">
          <h2>Findings</h2>
          <p>
            {product} · {stream || "every branch"} · {variant || "every variant"} — one row per
            component, so you can see where the weight is before deciding what to read.
          </p>
        </div>
        {controls}
        <ByComponent
          at={{ product, stream, variant }}
          // The same question the by-issue view asks, built in the one place
          // that builds it. This was a hand-copied subset of nine filters, so
          // switching views quietly widened the list back out by everything
          // the subset left out — a deadline, an assignee, an outcome — while
          // the chips above went on saying they were on.
          query={query}
          offset={offset}
          size={page}
          onHide={hide}
          onSort={(key) => set("sort", key)}
          onOnly={(name) => {
            const next = new URLSearchParams(params);
            next.delete("view");
            next.delete("offset");
            next.set("component", name);
            setParams(next);
          }}
          onPage={(next) => {
            const now = new URLSearchParams(params);
            if (next === 0) now.delete("offset");
            else now.set("offset", String(next));
            setParams(now);
          }}
        />
      </>
    );
  }

  if (findings.isPending) return <Loading />;
  if (findings.isError) {
    return <Failed error={findings.error} what="The findings could not be read." />;
  }

  // Names carried at more than one version on this page. They read as repeats
  // and are not: a build that vendors a library twice ships two of it.
  const seen = new Map<string, Set<string>>();
  for (const row of rows) {
    const versions = seen.get(row.component ?? "") ?? new Set<string>();
    versions.add(row.version ?? "");
    seen.set(row.component ?? "", versions);
  }
  const sameName = new Set(
    [...seen.entries()].filter(([, versions]) => versions.size > 1).map(([name]) => name),
  );
  // What is on this page, in the same key the selection uses.
  const shownKeys = rows.map(
    (row) => `${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`,
  );

  const overCap = bulkCap > 0 && picked.size > bulkCap;

  // Handing a selection to somebody, which is the one thing a selection can do
  // until the bulk workflows that start from one are built.
  async function handOver() {
    const who = handing.slice(handing.indexOf(":") + 1);
    const team = handing.startsWith("team:");
    // Every row picked, wherever it was picked, and the failures are counted
    // rather than thrown away: a loop that stops partway through leaves some
    // of a selection handed over and the rest not, and saying nothing about
    // that is worse than either outcome.
    const failed: string[] = [];
    const handled: string[] = [];
    for (const [key, row] of picked) {
      handled.push(key);
      try {
        await hand.mutateAsync({ row, who, team });
      } catch {
        failed.push(key);
      }
    }
    // Once, after the loop. On every write it put a list refetch between
    // each of them, so a long selection spent its time refetching.
    void queries.invalidateQueries({ queryKey: ["findings"] });
    void queries.invalidateQueries({ queryKey: ["holdings"] });
    // What is selected *now*, minus what went through. Written from the
    // snapshot the loop began with, anything ticked while it ran — eight
    // seconds for fifty rows, with the checkboxes live throughout — was
    // discarded and the count dropped with nothing explaining it.
    const sent = new Set(failed);
    setPicked((prev) => {
      const left = new Map(prev);
      for (const key of handled) {
        if (!sent.has(key)) left.delete(key);
      }
      return left;
    });
    setHanding("");
    setHandFailed(failed.length);
  }

  return (
    <>
      <div className="screen-head">
        <h2>
          Findings{" "}
          {/* Beside the heading, not only at the foot of the list. Choosing a
              filter is the moment somebody wants to know what it did, and a
              count that lives under a page of rows is a scroll away from the
              control that changed it. */}
          <span className="n" title="Matching the filters in force">
            {findings.isPending ? "…" : total.toLocaleString()}
          </span>
        </h2>
        <p>
          {spanning ? (
            <>
              Every product you can read — one row per issue and component, however many places it
              sits at. Each product&rsquo;s own triage line still applies, and the minimum severity
              here raises it rather than lowering it.
            </>
          ) : (
            <>
              {product} · {stream || "every branch"} · {variant || "every variant"} — one row per
              issue and component, however many places it sits at.
            </>
          )}
        </p>
      </div>

      {controls}

      <p className="hint" style={{ margin: "0 0 8px" }}>
        Ordered by urgency: exploited, then customer-facing, then severity, then EPSS. Click a row
        to open the finding; the plus previews it in place without going there.
      </p>

      {handFailed > 0 && (
        <p className="alert" role="status">
          {handFailed === 1
            ? "One row could not be handed over and is still selected."
            : `${handFailed.toLocaleString()} rows could not be handed over and are still selected.`}
        </p>
      )}
      {picked.size > 0 && (
        <div className="batchbar" style={{ marginBottom: 8 }}>
          <span>
            <b>{picked.size.toLocaleString()} selected</b>
          </span>
          <span className="hint">
            across every page you have picked from — the list is read again after each decision, so
            a selection is by what a row is rather than where it sits
          </span>
          {/* The bound the deployment sets on one action, said here rather
              than met one refusal at a time: handing over is a request per
              row, so an unbounded selection is one click turning into as many
              round trips as the filter matched. */}
          {overCap && (
            <span className="alert" role="status">
              {bulkCap.toLocaleString()} at a time is what this deployment allows. Narrow the
              selection.
            </span>
          )}
          <span className="spacer" />
          {/* One lookup rather than a list of people beside a list of teams:
              both are parties, and at a hundred people a select is a list
              nobody can type toward. */}
          <div style={{ minWidth: 230 }}>
            <Holder
              product={product}
              value={null}
              placeholder="Assign to…"
              none="Nobody"
              onPick={(held) => setHanding(held ? `${held.kind}:${held.identity}` : "")}
            />
          </div>
          <button
            type="button"
            className="btn"
            disabled={!handing || hand.isPending || overCap}
            onClick={() => void handOver()}
          >
            {hand.isPending ? "Assigning…" : `Assign ${picked.size}`}
          </button>
          <button type="button" className="linkish" onClick={() => setPicked(new Map())}>
            Clear
          </button>
        </div>
      )}

      {sameName.size > 0 && (
        <p className="hint" style={{ margin: "0 0 8px" }}>
          {sameName.size === 1 ? "One component appears" : `${sameName.size} components appear`} at
          more than one version on this page. Those rows are not repeats — a build that vendors a
          library twice carries two of it.
        </p>
      )}

      {rows.length === 0 ? (
        <Empty
          title="Nothing matches what you are looking at."
          detail="Everything here is below the floor you set, or outside the filter."
        />
      ) : (
        <div className="findings">
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 54 }}>
                    <input
                      type="checkbox"
                      aria-label="Select every row shown"
                      checked={picked.size > 0 && shownKeys.every((key) => picked.has(key))}
                      onChange={(event) => {
                        const next = new Map(picked);
                        rows.forEach((row, at) => {
                          const key = shownKeys[at] ?? identityOf(row);
                          if (event.target.checked) next.set(key, row);
                          else next.delete(key);
                        });
                        setPicked(next);
                      }}
                    />
                  </th>
                  <th>{sortable("Severity")}</th>
                  {spanning && <th>Product</th>}
                  <th>Issue</th>
                  <th>Component</th>
                  {/* Both ends of the way down, middle collapsed. */}
                  <th>{oneBuild ? "Path" : "Build"}</th>
                  <th
                    className="num"
                    title="EPSS: published probability of exploitation. Orders findings of equal severity"
                  >
                    {sortable("EPSS")}
                  </th>
                  <th>Fixed in</th>
                  <th className="num">{sortable("Covers")}</th>
                  <th>{sortable("Due")}</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody id="findingRows">
                {rows.map((row, i) => {
                  const key = `${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`;
                  const at = pathTo(buildOf(row), row, carrying);
                  // How far it is decided comes from the server, defined the
                  // way the state filter defines it; a row does not guess from
                  // what the build argued away, which is a different claim by
                  // a different author.
                  const pill = decidedAs(row.state, row.sent_back);
                  return (
                    <Fragment key={key}>
                      <tr className="row" data-i={i} onClick={() => navigate(at)}>
                        {/* The two controls that belong to the row rather than
                            to what is in it. Side by side in one narrow cell:
                            stacked they read as two unrelated things, and the
                            checkbox drawn at the browser's default size looked
                            like it had arrived from another page. */}
                        <td className="rowpickcell" onClick={(event) => event.stopPropagation()}>
                          <div className="rowpick">
                            <input
                              type="checkbox"
                              aria-label={`Select ${row.vulnerability} in ${row.component}`}
                              checked={picked.has(key)}
                              onChange={(event) => {
                                const next = new Map(picked);
                                if (event.target.checked) next.set(key, row);
                                else next.delete(key);
                                setPicked(next);
                              }}
                            />
                            <button
                              type="button"
                              className="peek"
                              aria-expanded={peeking === key}
                              title="Preview without leaving the list"
                              onClick={(event) => {
                                event.stopPropagation();
                                setPeeking(peeking === key ? null : key);
                              }}
                            >
                              {peeking === key ? "▾" : "▸"}
                            </button>
                          </div>
                        </td>
                        <td>
                          <Severity word={row.severity} />
                          {row.score ? (
                            <span className="hint" style={{ marginLeft: 6 }}>
                              {row.score.toFixed(1)}
                            </span>
                          ) : null}
                        </td>
                        {/* Which product this row is about, where that varies.
                            It is the column the cross-product list exists for,
                            and the only one a product's own list would draw
                            the same value in for every row. */}
                        {spanning && (
                          <td>
                            <Link
                              to={`/products/${encodeURIComponent(row.product ?? "")}/findings`}
                              onClick={(e) => e.stopPropagation()}
                            >
                              {row.product}
                            </Link>
                          </td>
                        )}
                        <td>
                          <Link to={at} className="id" onClick={(e) => e.stopPropagation()}>
                            {row.vulnerability}
                          </Link>{" "}
                          <Exploited when={row.exploited} />
                          {/* The secondary signal. What somebody must not
                              miss is on the finding itself. */}
                          {row.undisclosed && (
                            <span
                              className="state waiting"
                              title={
                                row.disclose_at
                                  ? `Not disclosed. The embargo ends ${on(row.disclose_at)}`
                                  : "Not disclosed, with no end date set"
                              }
                            >
                              Embargoed
                            </span>
                          )}
                          {(() => {
                            const age = openFor(row.opened);
                            return age ? (
                              <span className="hint" style={{ marginLeft: 6 }}>
                                {age}
                              </span>
                            ) : null;
                          })()}
                          {/* The words people put on this. On the row
                              because the point of marking work is finding it
                              again in a list — a mark only the finding screen
                              showed would be one nobody sees. Each is a filter:
                              seeing one and asking for the rest is the whole
                              motion. */}
                          {/* One line of what the issue actually says. Fifty
                              rows otherwise read "CVE-2026-74280 ·
                              linux-image" fifty times, and telling two of them
                              apart cost a click each — which is the preview
                              control right beside it, used fifty times to do
                              what one line of text does at a glance. */}
                          {row.summary && (
                            <div className="summary" title={row.summary}>
                              {row.summary}
                            </div>
                          )}
                          {(row.tags ?? []).length > 0 && (
                            <span className="marks">
                              {(row.tags ?? []).map((tag) => (
                                <button
                                  key={tag}
                                  type="button"
                                  className="mark"
                                  title={`Everything marked ${tag}`}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    set("tag", tag);
                                  }}
                                >
                                  {tag}
                                </button>
                              ))}
                            </span>
                          )}
                        </td>
                        <td>
                          {/* The name opens the component; narrowing and
                              hiding are the two small acts beside it. The
                              name and its controls are one line — held
                              apart, the column sized itself to the name and
                              then had nowhere to put them. */}
                          <span className="compline">
                            <Link
                              className="linkish id compname"
                              title={`Open ${row.component}`}
                              to={`/products/${encodeURIComponent(product)}/components/${encodeURIComponent(row.component ?? "")}`}
                              onClick={(event) => event.stopPropagation()}
                            >
                              {row.component}
                            </Link>
                            <button
                              type="button"
                              className="linkish onlyit"
                              title={`Everything open against ${row.component}`}
                              onClick={(event) => {
                                event.stopPropagation();
                                set("component", row.component ?? "");
                              }}
                            >
                              only
                            </button>
                            <button
                              type="button"
                              className="linkish hideit"
                              title={`Hide ${row.component} from this list`}
                              onClick={(event) => {
                                event.stopPropagation();
                                hide(row.component ?? "");
                              }}
                            >
                              hide
                            </button>
                          </span>
                          <br />
                          <span className="id" style={{ color: "var(--faint)" }}>
                            {row.version}
                          </span>
                          {/* The same issue at two binaries of one source
                              package is two rows here and one piece of work
                              everywhere else: it is decided once, upgraded
                              once, and routed by one rule. Said on the row
                              rather than folded away, because the places are
                              real and a reader counting them should get the
                              same number the list does — what they were not
                              told is that four of the rows are one bump. */}
                          {(siblings.get(`${row.vulnerability} ${row.source}`) ?? 0) ? (
                            <>
                              {" "}
                              <button
                                type="button"
                                className="linkish hint"
                                title={`Everything open against the ${row.source} source package`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  navigate(
                                    `/products/${encodeURIComponent(
                                      row.product || product,
                                    )}/components/${encodeURIComponent(row.component ?? "")}`,
                                  );
                                }}
                              >
                                {row.source} · also at{" "}
                                {siblings.get(`${row.vulnerability} ${row.source}`)} sibling
                                {(siblings.get(`${row.vulnerability} ${row.source}`) ?? 0) === 1
                                  ? ""
                                  : "s"}
                              </button>
                            </>
                          ) : null}
                        </td>
                        <td>
                          <Sits row={row} />
                        </td>
                        <td className="num hint">
                          {row.likelihood ? row.likelihood.toFixed(3) : "—"}
                        </td>
                        <td>
                          {(() => {
                            const said = upstreamSays(row.fix_state, row.fixed_in);
                            return (
                              <>
                                {/* A version is one token to a reader. Left
                                    to itself the browser breaks at every
                                    hyphen, so "1.26.0-rc.3" arrived as two
                                    lines and three versions as four — the
                                    tallest cell on the row, for a column that
                                    holds three short words. It still wraps,
                                    but only between one version and the
                                    next. */}
                                <span
                                  className={said.kind === "id" ? "id" : "hint"}
                                  style={
                                    said.kind === "faint" ? { color: "var(--faint)" } : undefined
                                  }
                                >
                                  {said.text.split(", ").map((one, n) => (
                                    <Fragment key={one}>
                                      {n > 0 ? ", " : null}
                                      <span className="whole">{one}</span>
                                    </Fragment>
                                  ))}
                                </span>
                                {row.matched === "identifier" && (
                                  <div
                                    className="hint"
                                    title="Matched by comparing a published identifier against an upstream version range. A distribution backports fixes without moving that version, so this may already be fixed here — nobody has confirmed either way."
                                  >
                                    not confirmed
                                  </div>
                                )}
                              </>
                            );
                          })()}
                        </td>
                        {/* Counted in the units somebody acts in. Deciding on
                            this row decides about every package and every
                            consumer under it, so those are the numbers shown —
                            a place count is a figure a reader cannot reconcile
                            with anything else on the screen. */}
                        <td className="num">
                          <span
                            title={`${row.places} ${row.places === 1 ? "finding" : "findings"} underneath`}
                          >
                            {row.packages > 1 && (
                              <>
                                {row.packages} packages
                                <span className="hint"> · </span>
                              </>
                            )}
                            {row.consumers} {row.consumers === 1 ? "consumer" : "consumers"}
                          </span>
                          {(row.answered ?? 0) > 0 && (
                            <span
                              className="hint"
                              title="Argued away by the build's own VEX, which is a different claim by a different author"
                            >
                              {" "}
                              · {row.answered} by the build
                            </span>
                          )}
                        </td>
                        <td>
                          {(() => {
                            const says = dueSays(row);
                            return (
                              <span
                                className={says.tone === "none" ? "hint" : `due ${says.tone}`}
                                title={
                                  says.tone === "none"
                                    ? "Nothing here is late, because nothing here is on a clock"
                                    : `Due ${row.due}`
                                }
                              >
                                {says.text}
                              </span>
                            );
                          })()}
                        </td>
                        <td>
                          <span className={`state ${pill.cls}`}>{pill.word}</span>
                        </td>
                      </tr>
                      {peeking === key && (
                        <tr className="places">
                          <td colSpan={10}>
                            <Peek
                              at={buildOf(row)}
                              vulnerability={row.vulnerability ?? ""}
                              component={row.component ?? ""}
                              version={row.version ?? ""}
                              to={at}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="cards">
            {rows.map((row) => {
              const at = pathTo(buildOf(row), row, carrying);
              return (
                // The only way to open a finding on a narrow screen, so it
                // has to be reachable without a pointer: a card that answers
                // a click and nothing else is a list nobody can get into
                // from a keyboard.
                <article
                  key={`${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`}
                  className={`fcard ${row.exploited ? "exploited" : (row.severity ?? "")}`}
                  role="link"
                  tabIndex={0}
                  aria-label={`${row.vulnerability} in ${row.component}`}
                  onClick={() => navigate(at)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      navigate(at);
                    }
                  }}
                >
                  <header>
                    <Severity word={row.severity} />
                    <Exploited when={row.exploited} />
                  </header>
                  <div>
                    <span className="id">{row.vulnerability}</span> in{" "}
                    <span className="id">{row.component}</span>
                  </div>
                  <div className="hint">
                    {row.packages > 1 && <>{row.packages} packages · </>}
                    {row.consumers} {row.consumers === 1 ? "consumer" : "consumers"} · fixed in{" "}
                    {row.fixed_in ?? "—"}
                  </div>
                </article>
              );
            })}
          </div>
        </div>
      )}

      <div className="filters" style={{ margin: "10px 0 0" }}>
        <span className="hint">
          Showing {rows.length.toLocaleString()} of {total.toLocaleString()}
          {(line.hidden ?? 0) > 0 && !below && (
            <>
              {" "}
              · {(line.hidden ?? 0).toLocaleString()} more are below what this product triages (
              {line.floor}). They are still recorded and still counted.
            </>
          )}
          {below && <> · showing what is below the line as well as above it.</>}
        </span>
        {(line.hidden ?? 0) > 0 && !below && (
          <button type="button" className="linkish" onClick={() => set("below", "yes")}>
            Include
          </button>
        )}
        {below && (
          <button type="button" className="linkish" onClick={() => set("below", "")}>
            Back to what is triaged
          </button>
        )}
        {/* The whole filtered list as a file, not the page. Opened through
            the browser so the session carries: the export is read with the
            same visibility as the screen.

            Offered when spanning too. The cross-product list has a file of its
            own and the filters mean the same thing on both, so hiding the
            control there left one narrowing reachable as a file and the other
            not, for no reason a reader could see. */}
        <span className="hint" style={{ display: "flex", gap: 6 }}>
          <span>Export</span>
          {(["csv", "json"] as const).map((as) => (
            <a key={as} className="linkish" href={`${exportsAt}.${as}?${asFile}`}>
              {as.toUpperCase()}
            </a>
          ))}
        </span>
        {total > PAGES[0] && (
          <label className="hint" style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            <span>Per page</span>
            <select
              aria-label="Rows per page"
              {...notACredential}
              style={{ width: "auto" }}
              value={String(page)}
              onChange={(event) => {
                const now = new URLSearchParams(params);
                now.delete("offset");
                if (Number(event.target.value) === PAGE) now.delete("page");
                else now.set("page", event.target.value);
                setParams(now);
              }}
            >
              {PAGES.map((each) => (
                <option key={each} value={String(each)}>
                  {each}
                </option>
              ))}
            </select>
          </label>
        )}
        <Pager offset={offset} total={total} size={page} onGo={go} />
      </div>
    </>
  );
}
