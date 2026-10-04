// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { matchPath, useLocation } from "react-router-dom";

import { ownsSession, SCOPE_KEPT } from "./drafts";
import {
  BUILD,
  ROUTES,
  allFindingsAt,
  buildFindingsAt,
  productAt,
  productFindingsAt,
  sameProductScreenAt,
  sameScreenAt,
  streamAt,
  streamsAt,
} from "./routes";

// The selection in hand.
//
// Read from the path rather than with useParams, because the frame is drawn
// outside the routes it wraps — useParams there is always empty, which is a
// silent kind of wrong: the rail and the picker never learn what was picked,
// and every screen below them works fine.
//
// A screen that names a build in its path is the authority for that build.
// Everything else — home, the queue, the product list — remembers the last one
// instead, so walking away from a build and back does not lose it.
// The findings list for anything wider than one build. The product is in the
// path because a list of findings is always a product's; the two levels below
// it ride in the query, which is the shape the server takes them in and the
// only shape that keeps them independent.
const LIST = ROUTES.productFindings;
// The same list with no product picked.
const EVERY = ROUTES.findings;

// Anything else under a product: every address below `/products/:product`
// names that product, and a shape added to the router without being listed
// still yields it. It names no branch or variant, so it keeps the ones
// remembered for the same product.
const UNDER = `${ROUTES.product}/*`;

// The exact shapes first, then anything else under a product.
const SHAPES = [`${BUILD}/*`, BUILD, ROUTES.stream, ROUTES.streams, ROUTES.product, UNDER];

export type Scoped = { product?: string; stream?: string; variant?: string };

// A screen at this path that needs a whole build.
//
// Five of them do, and their data exists for one build and no other: each is
// about a way down, and there is no dependency graph across branches. So the
// picker cannot go partial while somebody is standing on one — the levels that
// would say "all" are disabled there and say why, rather than accepting the
// choice and moving somebody somewhere it makes sense, which turns a filter
// into a jump nobody asked for.
//
// The findings list is not one of them. It is a build's list when it is given
// a build and answers for every build under the product when it is not, so it
// takes whatever the picker selects.
export function needsBuild(pathname: string): boolean {
  if (onFindings(pathname)) return false;
  return matchPath(`${BUILD}/*`, pathname) !== null || matchPath(BUILD, pathname) !== null;
}

// The findings list, at any of its three addresses: a build's,
// a product's, and every product's.
export function onFindings(pathname: string): boolean {
  return (
    pathname === EVERY ||
    matchPath(ROUTES.buildFindings, pathname) !== null ||
    matchPath(LIST, pathname) !== null
  );
}

// The address of the findings list for a selection.
//
// A whole build keeps the path it has, because the screens around it — the
// finding, the tree, the inventories — are that build's and share the prefix.
// Anything wider is the product's list carrying the levels that are set, so
// the address says what is being answered for and can be sent to somebody.
// The parameters the list writes into its own address when the address says
// nothing: no work lands in a tag, none lands in a release past end-of-life,
// and the by-issue view sets aside what a promised upgrade already answers.
//
// A figure counted without them opens a list that has them, which is how a
// number and the list behind it come to disagree in front of somebody. A link
// from such a figure carries them turned off, so the list asks what the figure
// was counted with.
export const UNNARROWED = "on=branch&on=tag&support=in-support&support=past-eol&planned=either";

//
// A filter a caller adds goes in as `extra`, never after the returned string:
// the address for a partial scope already carries a query, and a second `?`
// joined to it becomes part of the branch's name.
export function findingsPath(
  at: Scoped,
  unnarrowed = false,
  extra?: URLSearchParams | Record<string, string>,
): string {
  const query = new URLSearchParams();
  // Without a product it is the list across every product somebody can read,
  // which is the same screen. Sent to the catalog instead — the cross-product
  // list being a screen of its own, reached from its own rail entry — one list
  // would have two doors, and the one in the scope group would be dead
  // whenever no product is picked.
  let whole: { product: string; stream: string; variant: string } | undefined;
  if (at.product && at.stream && at.variant) {
    whole = { product: at.product, stream: at.stream, variant: at.variant };
  } else if (at.product) {
    if (at.stream) query.set("stream", at.stream);
    if (at.variant) query.set("variant", at.variant);
  }
  if (unnarrowed)
    for (const [name, value] of new URLSearchParams(UNNARROWED)) query.append(name, value);
  for (const [name, value] of new URLSearchParams(extra)) query.append(name, value);
  if (whole) return buildFindingsAt(whole, query);
  return at.product ? productFindingsAt(at.product, query) : allFindingsAt(query);
}

// The place the tab remembers a selection. Named beside the
// sign-out clear that takes it away, so the two cannot drift apart.
const KEPT = SCOPE_KEPT;

// Remembered for the tab rather than the browser: it is where somebody is
// working right now, not a preference, and a second tab looking at another
// product should not drag the first one with it.
export function remember(scope: Scoped) {
  try {
    window.sessionStorage.setItem(KEPT, JSON.stringify(scope));
  } catch {
    // A browser that refuses storage still works; it just forgets.
  }
}

// The event that opens the scope picker from somewhere other than its own
// buttons. The picker is drawn once, in the frame, and holds its own open
// state; a screen asking somebody to pick a scope opens that picker rather
// than drawing a second one.
const PICK = "openpsirt:pick-scope";

// Open the scope picker.
export function askForScope() {
  window.dispatchEvent(new Event(PICK));
}

// Call `open` whenever a screen asks for the scope picker.
export function onAskForScope(open: () => void): () => void {
  window.addEventListener(PICK, open);
  return () => window.removeEventListener(PICK, open);
}

// The kept selection, checked rather than asserted.
//
// The value reaches a URL path segment and a request's query string, and it
// comes from browser storage — which an older build of this application wrote,
// which a person can edit, and which a cast does not examine. A number or an
// object there would become `[object Object]` in a query parameter. So each
// level is taken only when it is a non-empty string, and anything else is
// forgotten.
//
// Nothing at all where the selection was somebody else's: the product they
// were in is a name the person here may hold no grant on.
function remembered(): Scoped {
  if (!ownsSession()) return {};
  try {
    const kept = window.sessionStorage.getItem(KEPT);
    if (!kept) return {};
    const raw: unknown = JSON.parse(kept);
    if (typeof raw !== "object" || raw === null) return {};
    const at = raw as Record<string, unknown>;
    const scope: Scoped = {};
    for (const level of ["product", "stream", "variant"] as const) {
      const value = at[level];
      if (typeof value === "string" && value) scope[level] = value;
    }
    return scope;
  } catch {
    // A malformed entry is not something a reader can act on, and throwing
    // here would take the screen down over a remembered preference.
    return {};
  }
}

// The picker's selection as query parameters, with the levels that cannot
// stand alone dropped. A branch or a variant without a product is refused by
// the server rather than guessed at, and sending one would only turn a
// selection nobody can make in the interface into an error.
export function scopeQuery(at: Scoped): Record<string, string> {
  if (!at.product) return {};
  return {
    product: at.product,
    ...(at.stream ? { stream: at.stream } : {}),
    ...(at.variant ? { variant: at.variant } : {}),
  };
}

export function useScope(): Scoped {
  const { pathname, search } = useLocation();
  const kept = remembered();
  const named = scopeAt(pathname, search, kept);
  if (!named) return kept;
  if (named.product) remember(named);
  return named;
}

// The scope an address names, or null where it names none and the tab's
// remembered one stands. An address under a product that names nothing below
// it, such as a component or an inbox, keeps the branch and variant
// remembered for that product, so walking into one does not widen the scope.
export function scopeAt(pathname: string, search: string, kept: Scoped = {}): Scoped | null {
  // The wider findings list is the one address whose scope is not all in the
  // path: the product is, and the two levels below it are in the query, which
  // is what lets either of them be "all" independently.
  const list = matchPath(LIST, pathname);
  if (list) {
    const asked = new URLSearchParams(search);
    return {
      product: list.params.product,
      stream: asked.get("stream") || undefined,
      variant: asked.get("variant") || undefined,
    };
  }
  for (const shape of SHAPES) {
    const hit = matchPath(shape, pathname);
    if (hit) {
      const { product, stream, variant } = hit.params;
      if (shape === UNDER && product === kept.product) return { ...kept };
      return { product, stream, variant };
    }
  }
  return null;
}

// The parts that survive a product change, per address that names a product.
//
// The name in the path is what these screens read, so remembering a different
// product and staying put means the path re-supplies the old one and the
// picker snaps back with nothing said. Each is rewritten instead — and what
// sits below the product in the address is dropped where it belongs to the
// product that was there: a branch is one product's, and so is a component.
const UNDER_PRODUCT: { shape: string; carries: "nothing" | "stream" | "tail" }[] = [
  { shape: ROUTES.stream, carries: "stream" },
  { shape: ROUTES.streams, carries: "tail" },
  { shape: ROUTES.variants, carries: "tail" },
  { shape: ROUTES.comparison, carries: "tail" },
  { shape: ROUTES.inventoryComparison, carries: "tail" },
  { shape: ROUTES.inbox, carries: "tail" },
  { shape: ROUTES.inboxReport, carries: "nothing" },
  { shape: ROUTES.productComponent, carries: "nothing" },
  { shape: ROUTES.product, carries: "tail" },
];

// where a scope change should land, given where somebody already is.
//
// Staying put is the point: changing what you are looking at is a property of
// the screen rather than a journey to another one, so a build-scoped screen
// swaps its build and everything else stays exactly where it was.
//
// Null means stay exactly where you are, which is right for every address that
// names nothing that changed — the review queue is nobody's product, and
// rewriting it would turn a filter into a jump.
export function rescoped(pathname: string, to: Scoped): string | null {
  const build = matchPath(`${BUILD}/*`, pathname) ?? matchPath(BUILD, pathname);
  if (build) {
    // A build-scoped screen exists for one build and no other, so a partial
    // selection has nowhere to land. The picker disables those levels while
    // somebody stands on one, so this is the belt rather than the braces.
    if (!to.product || !to.stream || !to.variant) return null;
    // Cut from the address as it stands rather than read from the match,
    // whose splat has an escaped slash turned back into a separator.
    const rest = pathname.slice(build.pathnameBase.length).replace(/^\//, "");
    return sameScreenAt({ product: to.product, stream: to.stream, variant: to.variant }, rest);
  }
  // The wider list carries the whole selection in its own address.
  if (matchPath(LIST, pathname)) return findingsPath(to);
  for (const { shape, carries } of UNDER_PRODUCT) {
    const hit = matchPath(shape, pathname);
    if (!hit) continue;
    // Every product, chosen from one product's screen, is the catalog.
    if (!to.product) return "/products";
    if (carries === "nothing") return productAt(to.product);
    if (carries === "tail") {
      const tail = shape.slice(ROUTES.product.length);
      return hit.params.product === to.product ? null : sameProductScreenAt(to.product, tail);
    }
    if (hit.params.product === to.product && hit.params.stream === to.stream) return null;
    return to.stream ? streamAt(to.product, to.stream) : streamsAt(to.product);
  }
  return null;
}
