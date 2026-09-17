import { overCapNotice, useBulkCap } from "../ui/bulk";
import { useSelection } from "./useSelection";
import { FindingsTable } from "./FindingsTable";
import { notACredential } from "../ui/noautofill";
import { ByBump, ByComponent, Pager, bumpQuery } from "./FindingsViews";
import { FLOORS } from "../ui/severities";
import { Filters, Narrowed, STATES, activeFilters, without, withoutAny } from "./FindingsFilters";
import { Choices } from "../ui/Choices";
import { useMemo, useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Icon } from "../ui/Icons";
import { Holder } from "../ui/Holder";
import { Saved, here, ruleIn, useKept } from "../ui/Saved";
import { said } from "../ui/Decide";
import { useKeepPlace } from "../app/keepPlace";
import { useWho } from "../app/session";
// The page sizes, the orders, the filters and where a row goes all live beside
// the list rather than in it, because the finding screen asks the same
// question of the server to offer the row before and the row after. Fifty rows
// is 153 pages of one product's findings, which is not a list anybody
// assembles a day's work out of.
import {
  BY_DEFAULT,
  LEAST_FIRST,
  ORDERS,
  PAGE,
  PAGES,
  SORTS,
  acrossProducts,
  asAsked,
  listQuery,
  pageSize,
  withEach,
  withParam,
  withParams,
  hidden,
  type Row,
  type SortWord,
  usePaging,
} from "./list";

// The filters the by-bump view can apply, by the key their chip carries.
//
// Six of the thirty-odd. The rest ask about a place, a deadline or an
// assignee, and a bump has none of those — so they are named on that screen
// rather than dropped, which is what would widen the list back out while the
// chips went on saying they were on.
const BUMPABLE = new Set(["q", "floor", "exploited", "component", "ecosystem", "state"]);

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
  // How many columns the header renders, so the preview row spans all of them.
  // Written as a literal it was one short on the spanning list, which draws
  // the product as a column of its own.
  const COLUMNS = spanning ? 11 : 10;
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
  const { offset, go } = usePaging();
  const page = pageSize(params);
  const sort = params.get("sort") ?? "";
  const ascending = params.get("asc") === "yes";
  const floor = params.get("floor") ?? "low";
  const view = params.get("view") ?? "issues";
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
  // Closed until somebody opens it. The panel is most of a screen, and what is
  // narrowed is already stated above the list as a chip per filter that removes
  // itself when clicked — so opening it because a filter is set covers the rows
  // somebody followed a link to read, to say what the chips say already.
  const [more, setMore] = useState(false);
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
  const {
    picked,
    pick,
    pickAll,
    clear: clearPicked,
    asking,
    failed: handFailed,
    through,
  } = useSelection(asked);
  // Beside the hooks it belongs with: this reads the session, so it cannot sit
  // after an early return.
  const { cap: bulkCap, over: overCap } = useBulkCap(picked.size);
  const me = useWho();
  const [handing, setHanding] = useState("");
  // The list somebody has turned down a prepared claim for, as its address.
  // Kept rather than derived, because "do not use it" is an answer about the
  // list on screen — narrowing further asks a different question, and the rule
  // is offered again.
  const [declined, setDeclined] = useState<string | null>(null);
  const [typed, setTyped] = useState(searching);
  // The direction an order opens at, which is not the same for all of them:
  // "sort by severity" means the worst first and "sort by due" means the
  // soonest, and both were opening most-first.
  function firstAsk(key: SortWord): Record<string, string> {
    return { sort: key === BY_DEFAULT ? "" : key, asc: LEAST_FIRST.includes(key) ? "yes" : "" };
  }

  // A column header that orders by itself. Clicking the one already sorted
  // turns it around; clicking another opens it the way round that column
  // means.
  function sortable(label: keyof typeof SORTS) {
    const key = SORTS[label];
    const on = sort === key;
    return (
      <button
        type="button"
        className="linkish"
        title={`Order by ${label.toLowerCase()}`}
        onClick={() => {
          if (on) {
            ask(withParam(asked, "asc", ascending ? "" : "yes"));
            return;
          }
          setEach(firstAsk(key));
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

  // What a saved filter prepares, where this list is exactly one somebody kept
  // and that one prepares anything. Read off the address rather than
  // remembered from the pick: a rule that outlived the narrowing it was picked
  // for would prefill rows it never drew, with somebody's name about to go on
  // the claim — and one remembered on the screen is lost coming back from a
  // finding, leaving the dropdown saying it is open while no row carries it.
  //
  // Offered and never applied: a named person submits the claim as their own.
  // The filter's name travels with every row, which is how a finding opened
  // from here knows to fill its form in.
  const kept = useKept(product, !spanning);
  const prepared = useMemo(() => {
    if (declined === here(params)) return null;
    const one = ruleIn(kept.data?.items ?? [], params);
    return one?.prepares ? { name: one.name, prepares: one.prepares } : null;
  }, [kept.data, params, declined]);

  const queries = useQueryClient();
  // What one action may write here, as the deployment sets it. A selection is
  // handed over a row at a time, so this is the bound on how many round trips
  // one click makes. Read up here with the other hooks, because the screen
  // returns early for two of its views.

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

  // What each view would show, on the button that switches to it.
  //
  // The three answer the same narrowing at three grains, and the difference
  // between them is the whole reason to switch: a product whose by-issue list
  // is 7,455 rows is 341 by component and 284 by upgrade, and nothing said so
  // — so the list opened on its longest view and read as the only one.
  //
  // Asked with a page of one, because the total is what is wanted. The
  // by-issue count is the one the screen already holds where the by-issue view
  // is what is drawn, so it is asked only from the other two. The by-upgrade
  // count is a fix-bundle aggregate, measured at 2.2 s against a backlog of
  // 8,376 — held for five minutes rather than asked again as somebody pages.
  const byIssue = useQuery({
    queryKey: ["findings", "count", product, stream, variant, query],
    enabled: view !== "issues",
    staleTime: 5 * 60_000,
    queryFn: async () =>
      unwrap(
        spanning
          ? await api.GET("/v1/findings", {
              params: { query: { ...acrossProducts(query), limit: 1, offset: 0 } },
            })
          : await api.GET("/v1/products/{product}/findings", {
              params: {
                path: { product },
                query: { ...query, ...selection, limit: 1, offset: 0 },
              },
            }),
      ),
  });
  const byComponent = useQuery({
    queryKey: ["findings-by-component", "count", product, selection, query],
    enabled: !spanning,
    staleTime: 5 * 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings/components", {
          params: {
            path: { product },
            query: {
              ...(query as unknown as Record<string, never>),
              ...selection,
              limit: 1,
              offset: 0,
            },
          },
        }),
      ),
  });
  const byUpgrade = useQuery({
    queryKey: ["fix-bundles", "count", product, selection, query],
    enabled: !spanning,
    staleTime: 5 * 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/fix-bundles", {
          params: {
            path: { product },
            query: bumpQuery({ product, ...selection }, query, 1, 0) as Record<string, never>,
          },
        }),
      ),
  });

  // Where somebody was, restored when they come back. This is the screen the
  // complaint is about: opening a finding and pressing back rebuilt the list
  // at the top of it, eighteen rows above where they had been reading.
  useKeepPlace(findings.isSuccess);

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

  // Every change to the question the list is asking goes through the hook that
  // holds the selection, which is where the rule that a changed question
  // clears it now lives.
  function ask(next: URLSearchParams) {
    setParams(asking(next));
  }

  function set(key: string, value: string) {
    ask(withParam(asked, key, value));
  }

  // Several filters in one act, for the controls that change two at once.
  function setEach(changes: Record<string, string>) {
    ask(withEach(asked, changes));
  }

  function setMany(key: string, values: string[]) {
    ask(withParams(asked, key, values));
  }

  function hide(component: string) {
    ask(hidden(asked, component));
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
          {/* Across every product there is no by-component or by-bump answer
              to give: both ask a product-scoped endpoint, and asked with no
              product they are refused for a path parameter that is missing.
              Offered anyway, the two buttons were controls that could only
              produce an error — and switching to one and back is how somebody
              loses the question they had built. */}
          {[
            ["issues", "By issue", view === "issues" ? total : byIssue.data?.total],
            ...(spanning ? [] : [["components", "By component", byComponent.data?.total] as const]),
            ...(spanning ? [] : [["bumps", "By upgrade", byUpgrade.data?.total] as const]),
          ].map(([value, label, count]) => (
            <button
              key={value}
              type="button"
              aria-pressed={view === value}
              onClick={() => set("view", value === "issues" ? "" : (value as string))}
            >
              {label}
              {typeof count === "number" && <span className="n">{count.toLocaleString()}</span>}
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
            onPicked={() => {
              ask(new URLSearchParams(asked));
              setDeclined(null);
            }}
          />
        )}
        {/* Which order the list is in, said rather than inferred. Four of the
            six sit under a column header, so the two that do not — the tool's
            own ranking and how long something has been open — could not be
            asked for at all, and the ranking could not be got back to once a
            header had been clicked. */}
        <span className="floor">
          <span style={{ color: "var(--faint)" }}>Order</span>
          <select
            aria-label="Order the list"
            value={sort || BY_DEFAULT}
            onChange={(event) => setEach(firstAsk(event.target.value as SortWord))}
          >
            {Object.entries(ORDERS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </span>
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
        // Through the same function every other change goes through, so the
        // invariant above holds by construction rather than by a property of
        // the chips: today every chip either drops its key or puts the wider
        // default back, so removing one only ever widens and the surviving
        // selection still matches. One chip whose removal narrowed would
        // re-open exactly the write that rule was added for.
        clear={(chip) => ask(without(asked, chip))}
        clearAll={() => ask(withoutAny(asked))}
      />

      {more && (
        <Filters
          params={asked}
          set={set}
          setEach={setEach}
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
            Every finding opened from this list fills its decision form in, saying{" "}
            <b>{said(prepared.prepares.outcome ?? "")}</b> in the words “{prepared.name}” carries
            {prepared.prepares.defer_days ? (
              <>, put off {prepared.prepares.defer_days} days from whenever you submit it</>
            ) : null}
            . Nothing is proposed until you submit it, and it goes out as <b>your</b> claim for a
            second person to agree to.
          </span>
          <button
            type="button"
            className="linkish"
            style={{ marginLeft: "auto" }}
            onClick={() => setDeclined(here(params))}
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
            Under {beneath} ×
          </button>
        </div>
      )}
    </>
  );

  // A view the query string still asks for after the product went away —
  // somebody narrowing a product's list by component and then clearing the
  // product. The list is the one that spans, rather than an error.
  if (spanning && view !== "issues") {
    const asking = new URLSearchParams(params);
    asking.delete("view");
    return <Navigate replace to={`/findings?${asking}`} />;
  }

  if (view === "bumps") {
    return (
      <>
        <div className="screen-head">
          <h2>Findings</h2>
          <p>
            {product} · {stream || "every branch"} · {variant || "every variant"}
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
          // rather than dropped quietly — and the three this view does take
          // take one value each, so a second value asked for is named here
          // too rather than sent nowhere while the chip above says it is on.
          cannot={[
            ...activeFilters(asked)
              .filter((each) => !BUMPABLE.has(each.key))
              .map((each) => each.label),
            ...activeFilters(asked)
              .filter((each) => BUMPABLE.has(each.key) && asked.getAll(each.key).length > 1)
              .map((each) => each.label + " past the first"),
          ]}
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
            {product} · {stream || "every branch"} · {variant || "every variant"}
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

  // What is on this page, in the same key the selection uses.
  const shownKeys = rows.map(
    (row) => `${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`,
  );

  // Handing a selection to somebody, which is the one thing a selection can do
  // until the bulk workflows that start from one are built. What a refusal
  // partway through leaves behind is the hook's rule rather than this one's.
  async function handOver(to?: string) {
    const who = to ?? handing.slice(handing.indexOf(":") + 1);
    const team = to === undefined && handing.startsWith("team:");
    await through((row: Row) => hand.mutateAsync({ row, who, team }));
    // Once, after the loop. On every write it put a list refetch between each
    // of them, so a long selection spent its time refetching.
    void queries.invalidateQueries({ queryKey: ["findings"] });
    void queries.invalidateQueries({ queryKey: ["holdings"] });
    setHanding("");
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
            <>Every product you can read</>
          ) : (
            <>
              {product} · {stream || "every branch"} · {variant || "every variant"}
            </>
          )}
        </p>
      </div>

      {controls}

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
          <span className="hint">across pages</span>
          {/* The bound the deployment sets on one action, said here rather
              than met one refusal at a time: handing over is a request per
              row, so an unbounded selection is one click turning into as many
              round trips as the filter matched. */}
          {overCap && (
            <span className="alert" role="status">
              {overCapNotice(bulkCap)}
            </span>
          )}
          <span className="spacer" />
          {/* Taking unowned work needs no more right than reaching this list
              does and no product chosen, so it is a button rather than a step
              through a picker that may have nobody in it. */}
          <button
            type="button"
            className="btn"
            disabled={me.data?.identity == null || hand.isPending || overCap}
            onClick={() => void handOver(me.data!.identity)}
          >
            {`Take ${picked.size}`}
          </button>
          {/* One lookup rather than a list of people beside a list of teams:
              both are parties, and at a hundred people a select is a list
              nobody can type toward.

              Who may hold work is a question about one product, and this list
              answers for every product a reader can see when none is picked —
              so the control says that instead of opening on nobody. */}
          <div style={{ minWidth: 230 }}>
            <Holder
              product={product}
              value={null}
              placeholder={product ? "Assign to…" : "Pick a product to assign"}
              none="Nobody"
              disabled={!product}
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
          <button type="button" className="linkish" onClick={clearPicked}>
            Clear
          </button>
        </div>
      )}

      {rows.length === 0 ? (
        <Empty title="Nothing matches these filters." />
      ) : (
        <FindingsTable
          rows={rows}
          shownKeys={shownKeys}
          picked={picked}
          pick={pick}
          pickAll={pickAll}
          spanning={spanning}
          columns={COLUMNS}
          oneBuild={oneBuild}
          sortable={sortable}
          buildOf={buildOf}
          siblings={siblings}
          carrying={carrying}
          prepared={prepared}
          set={set}
          hide={hide}
          peeking={peeking}
          setPeeking={setPeeking}
        />
      )}

      <div className="filters" style={{ margin: "10px 0 0" }}>
        <span className="hint">
          Showing {rows.length.toLocaleString()} of {total.toLocaleString()}
          {(line.hidden ?? 0) > 0 && !below && (
            <>
              {" "}
              · {(line.hidden ?? 0).toLocaleString()} below the {line.floor} line
            </>
          )}
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
