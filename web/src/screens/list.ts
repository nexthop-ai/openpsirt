import { useSearchParams } from "react-router-dom";

import type { Body } from "../api/client";

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

// The orders the server offers, by the word it takes and the column they sit
// under. Named here rather than derived from the headers, because the server's
// allowlist is the authority and a header that offered an order it does not
// have would simply stop sorting.
export const SORTS = {
  Severity: "severity",
  EPSS: "epss",
  Covers: "places",
  Due: "deadline",
} as const;

// What the by-issue list asks when the address has not said: the work a
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

// Which build the list is looking at. Either may be absent: the list is not
// one of the screens that needs a whole build.
export function where(params: URLSearchParams) {
  const stream = params.get("stream") ?? "";
  const variant = params.get("variant") ?? "";
  return { ...(stream ? { stream } : {}), ...(variant ? { variant } : {}) };
}

// How many rows a page holds, as the address says, refusing a size that is not
// offered — the number reaches the server as a limit and the screen as a page.
export function pageSize(params: URLSearchParams): number {
  const asked = Number(params.get("page"));
  return PAGES.includes(asked as (typeof PAGES)[number]) ? asked : PAGE;
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
  // Which sort of release, and whether it is still in support. Two questions
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
  return {
    limit: pageSize(params),
    offset: Number(params.get("offset") ?? 0),
    ...(sort ? { sort: sort as (typeof SORTS)[keyof typeof SORTS] } : {}),
    ...(sort && params.get("asc") === "yes" ? { asc: true } : {}),
    ...(floor !== "low" ? { severity: floor as "low" | "medium" | "high" | "critical" } : {}),
    ...(exploited ? { exploited: true } : {}),
    ...(fixable ? { fixable: true } : {}),
    ...(likelihood > 0 && likelihood <= 1 ? { epss_at_least: likelihood } : {}),
    ...(params.get("opened_after") ? { opened_after: params.get("opened_after") ?? "" } : {}),
    ...(params.get("proposed_after") ? { proposed_after: params.get("proposed_after") ?? "" } : {}),
    ...(params.get("closed_after") ? { closed_after: params.get("closed_after") ?? "" } : {}),
    ...(params.get("q") ? { q: params.get("q") ?? "" } : {}),
    ...(ecosystems.length > 0 ? { ecosystem: ecosystems } : {}),
    ...(releases.length > 0 ? { on: releases as ("branch" | "tag")[] } : {}),
    ...(support.length > 0 ? { support: support as ("in-support" | "past-eol")[] } : {}),
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
    ...(params.get("open_for") ? { open_for: Number(params.get("open_for")) } : {}),
    ...(running === "overdue" ? { overdue: true } : {}),
    ...(running && running !== "overdue" ? { due_within: Number(running) } : {}),
    ...(params.get("sent_back") === "1" ? { sent_back: true } : {}),
    ...(params.get("differs") === "1" ? { differs: true } : {}),
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
    ...(params.get("recorded") === "1" ? { recorded: true } : {}),
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
  const { beneath, differs, ...rest } = query as ReturnType<typeof listQuery> & {
    beneath?: string;
    differs?: boolean;
  };
  void beneath;
  void differs;
  return rest;
}

// What makes a row that row, for finding it again in a list read afresh.
export function identityOf(row: Row): string {
  return `${row.vulnerability} ${row.component} ${row.version} ${row.ecosystem ?? ""}`;
}

// Where a row opens. The version is part of the address: a component name is
// not unique within a build. It carries the list it came from so the finding
// can offer the row before and the row after. The list's address travels as
// one value rather than as its own parameters, so a filter added to the list
// needs nothing here and cannot collide with a name the finding screen already
// uses.
export function pathTo(
  at: { product: string; stream: string; variant: string },
  // Only the three fields the address is built from, so that what a caller has
  // to hold is what a link needs rather than a whole row.
  row: Pick<Row, "vulnerability" | "component" | "version">,
  from?: string,
): string {
  const query = new URLSearchParams();
  if (row.version) query.set("version", row.version);
  // Set even when it is empty, because an unfiltered list is still a list: the
  // finding tells "there was no list" from "the list asked for everything" by
  // whether the parameter is there at all, and the second one has a row before
  // and a row after exactly like the first.
  if (from !== undefined) query.set("from", from);
  const asked = query.toString();
  return (
    `/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}` +
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
// does not.
export function windowFor(offset: number, limit: number): { offset: number; limit: number } {
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

// Where a list is paged to, kept in its address.
//
// The offset lives in the address for the reason every filter does: a page
// somebody sends is the page they were looking at. Five screens each had
// their own copy of this — read the offset, clone the parameters, delete it
// or set it, write them back — and the rule that keeps a first page's address
// clean, deleting rather than setting zero, was five chances to write
// `?offset=0` into a link.
export function usePaging(): { offset: number; go: (to: number) => void } {
  const [params, setParams] = useSearchParams();
  const offset = Number(params.get("offset") ?? 0);
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
