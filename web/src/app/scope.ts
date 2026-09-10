import { matchPath, useLocation } from "react-router-dom";

// What you are looking at.
//
// Read from the path rather than with useParams, because the frame is drawn
// outside the routes it wraps — useParams there is always empty, which is a
// silent kind of wrong: the rail and the picker never learn what was picked,
// and every screen below them works fine.
//
// A screen that names a build in its path is the authority for that build.
// Everything else — home, the queue, the product list — remembers the last one
// instead, so walking away from a build and back does not lose it.
const BUILD = "/products/:product/streams/:stream/variants/:variant";
// The findings list for anything wider than one build. The product is in the
// path because a list of findings is always a product's; the two levels below
// it ride in the query, which is the shape the server takes them in and the
// only shape that keeps them independent.
const LIST = "/products/:product/findings";
// The same list with no product picked.
const EVERY = "/findings";

const SHAPES = [
  `${BUILD}/*`,
  BUILD,
  "/products/:product/streams/:stream",
  "/products/:product/streams",
  "/products/:product",
];

export type Scoped = { product?: string; stream?: string; variant?: string };

// Whether the screen at this path needs a whole build.
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

// Whether this is the findings list, at any of its three addresses: a build's,
// a product's, and every product's.
export function onFindings(pathname: string): boolean {
  return (
    pathname === EVERY ||
    matchPath(`${BUILD}/findings`, pathname) !== null ||
    matchPath(LIST, pathname) !== null
  );
}

// Where the findings list for a selection lives.
//
// A whole build keeps the path it has, because the screens around it — the
// finding, the tree, the inventories — are that build's and share the prefix.
// Anything wider is the product's list carrying the levels that are set, so
// the address says what is being answered for and can be sent to somebody.
export function findingsPath(at: Scoped): string {
  // Without a product it is the list across every product somebody can read ,
  // which is the same screen. It used to send people to the catalog instead,
  // because the cross-product list was a screen of its own reached from its
  // own rail entry — so one list had two doors and the one in the scope group
  // was dead whenever no product was picked.
  if (!at.product) return "/findings";
  const product = `/products/${encodeURIComponent(at.product)}`;
  if (at.stream && at.variant) {
    return (
      `${product}/streams/${encodeURIComponent(at.stream)}` +
      `/variants/${encodeURIComponent(at.variant)}/findings`
    );
  }
  const query = new URLSearchParams();
  if (at.stream) query.set("stream", at.stream);
  if (at.variant) query.set("variant", at.variant);
  const rest = query.toString();
  return `${product}/findings${rest ? `?${rest}` : ""}`;
}

const KEPT = "openpsirt.scope";

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

function remembered(): Scoped {
  try {
    const kept = window.sessionStorage.getItem(KEPT);
    return kept ? (JSON.parse(kept) as Scoped) : {};
  } catch {
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
  // The wider findings list is the one address whose scope is not all in the
  // path: the product is, and the two levels below it are in the query, which
  // is what lets either of them be "all" independently.
  const list = matchPath(LIST, pathname);
  if (list) {
    const asked = new URLSearchParams(search);
    const scope = {
      product: list.params.product,
      stream: asked.get("stream") || undefined,
      variant: asked.get("variant") || undefined,
    };
    if (scope.product) remember(scope);
    return scope;
  }
  for (const shape of SHAPES) {
    const hit = matchPath(shape, pathname);
    if (hit) {
      const { product, stream, variant } = hit.params;
      const scope = { product, stream, variant };
      if (product) remember(scope);
      return scope;
    }
  }
  return remembered();
}

// where a scope change should land, given where somebody already is.
//
// Staying put is the point: changing what you are looking at is a property of
// the screen rather than a journey to another one, so a build-scoped screen
// swaps its build and everything else stays exactly where it was.
export function rescoped(pathname: string, to: Required<Scoped>): string | null {
  const hit = matchPath(`${BUILD}/*`, pathname) ?? matchPath(BUILD, pathname);
  if (!hit) {
    // The wider list, handed a whole build, becomes that build's own list —
    // which is the same screen at the address the rest of the build shares.
    return matchPath(LIST, pathname) ? findingsPath(to) : null;
  }
  const rest = (hit.params as { "*"?: string })["*"] ?? "";
  const base =
    `/products/${encodeURIComponent(to.product)}` +
    `/streams/${encodeURIComponent(to.stream)}` +
    `/variants/${encodeURIComponent(to.variant)}`;
  return rest ? `${base}/${rest}` : `${base}/findings`;
}
