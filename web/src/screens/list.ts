import { useSearchParams } from "react-router-dom";

import type { Body } from "../api/client";
import type { operations } from "../api/schema";

// The findings list, apart from the screen that draws it.
//
// Every filter lives in the address, which is what makes a list a link
// somebody can send. It is also what lets a finding walk the list it came
// from: the finding screen is handed the list's own address and asks
// the same question of the server, so the row before and the row after are the
// ones that were on screen — under the same filters, in the same order, and
// counted the same way. Two places building that query from the address is two
// places for it to drift, so it is built once, here.

export type Row = Body<"FindingBody">;

export const PAGES = [50, 100, 200] as const;
export const PAGE = PAGES[0];

// The most the server returns in one request. Named because walking off the
// end of a page asks for a row either side of it, and at the largest page
// there is no room to ask.
const MOST = 200;

// The word the server takes for one order, read out of the generated client.
//
// The server derives its own enum from the one list that says which orders
// exist, so this is the authority arriving here rather than a copy of it: a
// word dropped there is a compile error at the header that offers it, instead
// of a column that quietly stops sorting when the request is refused.
export type SortWord = NonNullable<
  NonNullable<operations["list-findings"]["parameters"]["query"]>["sort"]
>;

// The orders this list offers as column headers, by the column they sit under.
//
// Four of the six. The other two are in the order control above the list:
// `urgency` has no column because it is composed from four signals, and `age`
// has none because the table is already wider than a laptop.
export const SORTS = {
  Severity: "severity",
  EPSS: "epss",
  Covers: "places",
  Due: "deadline",
} satisfies Record<string, SortWord>;

// Every order, by the word a reader picks it by.
//
// All six, checked against the server's own enum: an order the server gains
// and this list does not offer is a compile error here rather than a word
// nobody can reach. The list is ordered by urgency when nothing is asked —
// the tool's own ranking, and what REQ-32 exists for — and that was the one
// order with no name on screen and no way back to it once a column header had
// been clicked.
export const ORDERS = {
  urgency: "Urgency",
  severity: "Severity",
  epss: "EPSS",
  places: "Covers",
  deadline: "Due",
  age: "Age",
} satisfies Record<SortWord, string>;

// A date this many days back, as the address carries one.
//
// Written as the date rather than as "yesterday": every filter lives in the
// address so that a list is a link somebody can send, and a relative word
// would mean something different whenever it was opened.
export function daysBack(days: number, from = new Date()): string {
  const then = new Date(from);
  then.setUTCDate(then.getUTCDate() - days);
  return then.toISOString().slice(0, 10);
}

// The order the list is in when the address asks for none.
export const BY_DEFAULT: SortWord = "urgency";

// The orders that mean "least first" on the first ask.
//
// Most of them are "most first": the worst severity, the highest likelihood,
// the widest reach. Two are not, and both were opening at the end nobody
// wanted — Due sorted the furthest-away deadline first, which is the answer to
// a question nobody asks, and Age is a question about what has sat here
// longest.
export const LEAST_FIRST: readonly SortWord[] = ["deadline", "age"];

// Work nobody holds and nobody has decided, as filters on this list.
//
// One spelling, because three places open it: the sidebar entry, the badge
// beside that entry, and the route the old `/unassigned` address resolves
// through. The screen that used to answer this went — it asked the server a
// question with no decision predicate in it, so it counted differently from
// its own heading, and it carried no deadline, no age, no filters and no sort
// over a list that runs to thousands of rows.
export const UNOWNED = "assigned=nobody&state=undecided";
export const UNOWNED_LIST = `/findings?${UNOWNED}`;

// The by-issue list's own default, where the address has not said: the work a
// promised upgrade already answers is out of view, because deciding it again
// one finding at a time is the thing the promise was made instead of.
//
// Written into the address rather than applied quietly on the way to the
// server, so it is a chip above the list like every other filter and can be
// removed by clicking it. A list that narrows itself and does not say so is
// how two people read one screen and disagree about what it holds. The
// by-component view is where an upgrade is managed, so it is untouched.
export function asAsked(params: URLSearchParams, view: string): URLSearchParams {
  const next = new URLSearchParams(params);
  if (view === "issues" && !params.has("planned")) next.set("planned", "unplanned");
  // The two questions about the release itself, on every view: no work lands
  // in a tag whatever anybody decides, and none lands in a release past
  // end-of-life either. Written into the address for the same reason the one
  // above is — a list that narrows itself and does not say so is how two
  // people read one screen and disagree about what it holds.
  if (!params.has("on")) next.set("on", "branch");
  if (!params.has("support")) next.set("support", "in-support");
  return next;
}

// The address the list is asking under, changed.
//
// Pure functions of the parameters, so they live beside the rest of what the
// address means rather than inside the screen that draws it. Every change
// drops the offset: a filter change lands somebody on page nine of a list with
// two pages, which draws as an empty list under a filter that matches plenty.

// The address a scope chip goes to when it is removed: the same list, one level
// wider, carrying every filter that was already on.
//
// The selection rides on the path rather than in the parameters, so widening is
// a move rather than a parameter change — and the filters have to be carried
// across by hand or removing the product chip would silently drop the narrowing
// somebody actually chose. `stream` and `variant` are dropped from what is
// carried because the address being built owns those: it puts back whichever of
// them the new scope still has.
export function widened(path: string, params: URLSearchParams): string {
  const rest = new URLSearchParams(params);
  rest.delete("stream");
  rest.delete("variant");
  // What is specific to a variant goes with the variant it was about. Left
  // standing, the chip says "only this variant" over a list narrowed by no
  // such thing, and the control offering it no longer has the value it holds.
  if (rest.get("variants") === "only") rest.delete("variants");
  const cut = path.indexOf("?");
  const base = cut < 0 ? path : path.slice(0, cut);
  const own = cut < 0 ? "" : path.slice(cut + 1);
  for (const [key, value] of new URLSearchParams(own)) rest.append(key, value);
  const query = rest.toString();
  return query ? `${base}?${query}` : base;
}

// withParam sets one value, or takes the key out where there is none.
export function withParam(params: URLSearchParams, key: string, value: string): URLSearchParams {
  return withEach(params, { [key]: value });
}

// withEach is several filters changed in one act.
//
// Two `withParam` calls in a row each build their change from the same
// parameters, so the second writes over the first — which is why unticking a
// box that also had to clear a shortcut could not turn the box off.
export function withEach(
  params: URLSearchParams,
  changes: Record<string, string>,
): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const [key, value] of Object.entries(changes)) {
    if (value) next.set(key, value);
    else next.delete(key);
  }
  return next;
}

// withParams is several values of one filter, which the address carries as the
// parameter repeated. Written whole rather than added to, so unticking the
// last one leaves no empty parameter behind.
export function withParams(
  params: URLSearchParams,
  key: string,
  values: string[],
): URLSearchParams {
  const next = new URLSearchParams(params);
  next.delete(key);
  for (const value of values) next.append(key, value);
  return next;
}

// hiding adds one component to what the list is asked to leave out.
export function hidden(params: URLSearchParams, component: string): URLSearchParams {
  const already = params.getAll("hide");
  return withParams(params, "hide", [...new Set([...already, component])]);
}

// The build the list is looking at. Either may be absent: the list is not
// one of the screens that needs a whole build.
export function where(params: URLSearchParams) {
  const stream = params.get("stream") ?? "";
  const variant = params.get("variant") ?? "";
  return { ...(stream ? { stream } : {}), ...(variant ? { variant } : {}) };
}

// The rows a page holds, as the address says, refusing a size that is not
// offered — the number reaches the server as a limit and the screen as a page.
export function pageSize(params: URLSearchParams): number {
  const asked = Number(params.get("page"));
  return PAGES.includes(asked as (typeof PAGES)[number]) ? asked : PAGE;
}

// A number the address carries, or nothing where it is not one.
//
// `Number("")` is 0 and `Number("soon")` is NaN, and both went to the server
// as they were: NaN reached it as the text "NaN" and 0 reached a parameter
// whose minimum is 1. The address is somebody else's text like any other, and
// a value outside what the server takes is a parameter to leave off rather
// than one to send wrong.
export function num(raw: string | null, least: number, most: number): number | undefined {
  if (raw === null || raw.trim() === "") return undefined;
  const asked = Number(raw);
  if (!Number.isFinite(asked) || asked < least || asked > most) return undefined;
  return asked;
}

// The filters, as the server takes them. Every value is narrowed to what the
// generated client will accept rather than asserted: a value the address
// carries is somebody else's text, and the client's types are the only place
// that says which words the server has.
// The components somebody has hidden from this page.
//
// Carried as the parameter repeated, like every other filter that takes a set,
// so the summary above the list can offer one chip each and take one back off.
// A comma-joined value is still read, because that is how it was written
// before and an address somebody saved should still open the list they saved.
export function hiddenIn(params: URLSearchParams): string[] {
  return [
    ...new Set(
      params
        .getAll("hide")
        .flatMap((each) => each.split(","))
        .map((each) => each.trim())
        .filter(Boolean),
    ),
  ];
}

export function listQuery(params: URLSearchParams) {
  const sort = params.get("sort") ?? "";
  const running = params.get("running") ?? "";
  const hiding = hiddenIn(params);
  const floor = params.get("floor") ?? "low";
  // Exploited and fix-available were one parameter holding one of two words,
  // so asking for both at once was not expressible — an accident of the
  // control they were drawn as rather than anything the server thinks. They
  // are two flags now; the old word is still read, so an address somebody
  // saved still opens the list they saved.
  const only = params.get("only") ?? "";
  const exploited = params.get("exploited") === "1" || only === "exploited";
  const fixable = params.get("fixable") === "1" || only === "hasFix";
  // Repeated in the address rather than one value, because "undecided or
  // waiting" is a question a single value could not ask.
  const states = params.getAll("state").filter(Boolean);
  const outcomes = params.getAll("outcome").filter(Boolean);
  const assigned = params.getAll("assigned").filter(Boolean);
  const fixStates = params.getAll("fix_state").filter(Boolean);
  const ecosystems = params.getAll("ecosystem").filter(Boolean);
  const declaredAs = params.getAll("declared_as").filter(Boolean);
  // The sort of release, and its support. Two questions
  // rather than one: a tag can be in support and a branch can be past its
  // date.
  const releases = params.getAll("on").filter(Boolean);
  const support = params.getAll("support").filter(Boolean);
  const vexStatus = params.getAll("vex_status").filter(Boolean);
  // The four somebody types into. Each is a set for the same reason the
  // closed lists are: a family of packages, a couple of somebody's own words,
  // two publishers, the memory-safety weaknesses. Any of them rather than all
  // of them — one row has one component name, so "both" would be nothing.
  const components = params.getAll("component").filter(Boolean);
  const tags = params.getAll("tag").filter(Boolean);
  const publishers = params.getAll("vex_publisher").filter(Boolean);
  const weaknesses = params.getAll("weakness").filter(Boolean);
  const likelihood = Number(params.get("epss_at_least") ?? "");
  // Both are a count of days the server takes from one upward, so a word, an
  // empty box and a zero are all "do not ask about this" rather than values.
  const openFor = num(params.get("open_for"), 1, Number.MAX_SAFE_INTEGER);
  // The run that opened it, as the run screen links to. An identifier the
  // address carries is somebody else's text like any other, so a value that is
  // not a run number is a parameter to leave off rather than one to send wrong.
  const openedBy = num(params.get("opened_by_run"), 1, Number.MAX_SAFE_INTEGER);
  const dueWithin = running === "overdue" ? undefined : num(running, 1, Number.MAX_SAFE_INTEGER);
  return {
    limit: pageSize(params),
    offset: num(params.get("offset"), 0, Number.MAX_SAFE_INTEGER) ?? 0,
    ...(sort ? { sort: sort as (typeof SORTS)[keyof typeof SORTS] } : {}),
    ...(sort && params.get("asc") === "yes" ? { asc: true } : {}),
    ...(floor !== "low" ? { severity: floor as "low" | "medium" | "high" | "critical" } : {}),
    ...(exploited ? { exploited: true } : {}),
    ...(fixable ? { fixable: true } : {}),
    ...(likelihood > 0 && likelihood <= 1 ? { epss_at_least: likelihood } : {}),
    ...(params.get("opened_after") ? { opened_after: params.get("opened_after") ?? "" } : {}),
    ...(openedBy !== undefined ? { opened_by_run: openedBy } : {}),
    ...(params.get("proposed_after") ? { proposed_after: params.get("proposed_after") ?? "" } : {}),
    ...(params.get("closed_after") ? { closed_after: params.get("closed_after") ?? "" } : {}),
    ...(params.get("q") ? { q: params.get("q") ?? "" } : {}),
    ...(ecosystems.length > 0 ? { ecosystem: ecosystems } : {}),
    ...(releases.length > 0 ? { on: releases as ("branch" | "tag")[] } : {}),
    ...(support.length > 0 ? { support: support as ("in-support" | "past-eol")[] } : {}),
    ...(declaredAs.length > 0
      ? {
          declared_as: declaredAs as (
            | "required"
            | "optional"
            | "excluded"
            | "build"
            | "design"
            | "development"
            | "other"
            | "runtime"
          )[],
        }
      : {}),
    ...(params.get("under") ? { under: params.get("under") ?? "" } : {}),
    ...(params.get("beneath") ? { beneath: params.get("beneath") ?? "" } : {}),
    ...(params.get("under_build") === "yes" ? { under_build: true } : {}),
    ...(states.length > 0
      ? { state: states as ("undecided" | "waiting" | "agreed" | "lapsed")[] }
      : {}),
    ...(outcomes.length > 0
      ? {
          outcome: outcomes as (
            "affected" | "not-applicable" | "deferred" | "wont-fix" | "already-fixed"
          )[],
        }
      : {}),
    ...(assigned.length > 0 ? { assigned: assigned as ("me" | "somebody" | "nobody")[] } : {}),
    ...(params.get("reassessed") === "1" ? { reassessed: true } : {}),
    ...(params.get("unconfirmed") === "1" ? { unconfirmed: true } : {}),
    ...(fixStates.length > 0
      ? {
          fix_state: fixStates as ("fixed" | "none" | "wont-fix" | "unknown" | "mixed")[],
        }
      : {}),
    ...(weaknesses.length > 0 ? { weakness: weaknesses } : {}),
    ...(openFor !== undefined ? { open_for: openFor } : {}),
    ...(running === "overdue" ? { overdue: true } : {}),
    ...(dueWithin !== undefined ? { due_within: dueWithin } : {}),
    ...(params.get("sent_back") === "1" ? { sent_back: true } : {}),
    ...(params.get("differs") === "1" ? { differs: true } : {}),
    ...(params.get("variants") === "only" || params.get("variants") === "every"
      ? { across_variants: params.get("variants") as "only" | "every" }
      : {}),
    ...(publishers.length > 0 ? { vex_publisher: publishers } : {}),
    ...(vexStatus.length > 0
      ? {
          vex_status: vexStatus as (
            "not_affected" | "affected" | "fixed" | "under_investigation"
          )[],
        }
      : {}),
    ...(hiding.length > 0 ? { exclude: hiding } : {}),
    ...(components.length > 0 ? { component: components } : {}),
    ...(tags.length > 0 ? { tag: tags } : {}),
    ...(params.get("origin") ? { origin: params.get("origin") as "scanner" | "manual" } : {}),
    ...(params.get("planned") && params.get("planned") !== "either"
      ? { planned: params.get("planned") as "planned" | "unplanned" }
      : {}),
    ...(params.get("below") === "yes" ? { below_floor: true } : {}),
  };
}

// The same filters, minus the two that are statements about one build. A
// subtree is a walk over one build's edges and "differs between builds" is a
// statement about a selection, so neither has any meaning spanning products —
// and the cross-product route does not take them. Dropped here rather than
// left in the address, so switching a product off does not silently narrow by
// something the reader can no longer see or clear.
export function acrossProducts(query: ReturnType<typeof listQuery>) {
  const { beneath, differs, across_variants, ...rest } = query as ReturnType<typeof listQuery> & {
    beneath?: string;
    differs?: boolean;
    across_variants?: string;
  };
  void beneath;
  void differs;
  void across_variants;
  return rest;
}

// What is specific to a variant is a question about one of them, so the
// server refuses it where the selection names none. Dropped here for the
// same reason the two above are: a filter left in the address after the
// variant it was about is widened away narrows nothing and refuses the list.
export function withinVariant(query: ReturnType<typeof listQuery>, named: boolean) {
  if (named || query.across_variants !== "only") return query;
  const { across_variants, ...rest } = query;
  void across_variants;
  return rest;
}

// A row's own identity, for finding it again in a list read afresh.
export function identityOf(row: Row): string {
  return `${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`;
}

// The address a row opens. The version is part of it: a component name is
// not unique within a build. It carries the list it came from so the finding
// can offer the row before and the row after. The list's address travels as
// one value rather than as its own parameters, so a filter added to the list
// needs nothing here and cannot collide with a name the finding screen already
// uses.
//
// Opened through a saved filter that prepares a claim, the
// filter's name travels too, and the finding fills its decision form from what
// that filter prepares. The name rather than the words: the filter is the one
// place deciding what it says, and a copy in an address is a second one that
// goes stale the moment somebody saves over the name.
// The prefix one build's screens live under. Every address under a build
// shares, written once: four screens spelled it out by hand, and the copies
// cannot be checked against the router or against each other.
export function buildPath(at: { product: string; stream: string; variant: string }): string {
  return (
    `/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}`
  );
}

export function pathTo(
  at: { product: string; stream: string; variant: string },
  // Only the three fields the address is built from, so that what a caller has
  // to hold is what a link needs rather than a whole row.
  row: Pick<Row, "vulnerability" | "component" | "version">,
  from?: string,
  rule?: string,
): string {
  const query = new URLSearchParams();
  if (row.version) query.set("version", row.version);
  if (rule) query.set("rule", rule);
  // Set even when it is empty, because an unfiltered list is still a list: the
  // finding tells "there was no list" from "the list asked for everything" by
  // whether the parameter is there at all, and the second one has a row before
  // and a row after exactly like the first.
  if (from !== undefined) query.set("from", from);
  const asked = query.toString();
  return (
    buildPath(at) +
    `/findings/${encodeURIComponent(row.vulnerability ?? "")}` +
    `/components/${encodeURIComponent(row.component ?? "")}` +
    (asked ? `?${asked}` : "")
  );
}

// The window a finding asks for to know its neighbors: the page the list was
// showing, widened by one row at each end. Widening is what makes the walk
// continuous — the row before a page and the row after it are on other pages,
// and a reader who did not choose the page boundary should not stop at it.
//
// At the largest page there is no room to widen, because the server returns at
// most that many in one request. The walk then ends at the page edge rather
// than asking twice, which is the honest outcome: one request answers, or it
// does not — and the window is the page itself, unmoved. Widening backward
// alone shifted it back a row, so the last row of every page fell outside its
// own window; the finding screen locates itself in the window by identity, so
// it found nothing and the walk vanished at the largest page size.
export function windowFor(offset: number, limit: number): { offset: number; limit: number } {
  if (limit >= MOST) return { offset, limit: MOST };
  const start = Math.max(0, offset - 1);
  return { offset: start, limit: Math.min(MOST, limit + (offset - start) + 1) };
}

// The list's address as the neighbor should carry it: the same filters, at
// the page that neighbor sits on. Walking forward off the end of a page
// therefore leaves the list where the reader now is, rather than where they
// started.
export function fromAt(from: string, absolute: number, limit: number): string {
  const next = new URLSearchParams(from);
  const page = Math.floor(absolute / limit) * limit;
  if (page === 0) next.delete("offset");
  else next.set("offset", String(page));
  return next.toString();
}

// The page a list is on, kept in its address.
//
// The offset lives in the address for the reason every filter does: a page
// somebody sends is the page they were looking at. Five screens each had
// their own copy of this — read the offset, clone the parameters, delete it
// or set it, write them back — and the rule that keeps a first page's address
// clean, deleting rather than setting zero, was five chances to write
// `?offset=0` into a link.
export function usePaging(): { offset: number; go: (to: number) => void } {
  const [params, setParams] = useSearchParams();
  const offset = num(params.get("offset"), 0, Number.MAX_SAFE_INTEGER) ?? 0;
  return {
    offset,
    go(to: number) {
      const next = new URLSearchParams(params);
      if (to <= 0) next.delete("offset");
      else next.set("offset", String(to));
      setParams(next);
    },
  };
}
