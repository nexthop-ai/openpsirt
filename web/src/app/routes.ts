// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import table from "./routes.json";

// Every address this application answers, and every address into it the
// interface builds.
//
// The table is routes.json: the pattern the router matches for each screen,
// and the query parameters a link may set on it. The router is built from it,
// and so is every address below. The server builds the addresses its
// notifications carry in a package of its own, and that package is tested
// against the same file.
//
// An address put together from parts is put together here and nowhere else. A
// gate over the source fails on one built anywhere else, and on an address
// written out whole that no route answers.

type RouteName = keyof typeof table;

// The pattern the router matches, by screen.
export const ROUTES = Object.fromEntries(
  Object.entries(table).map(([name, route]) => [name, route.path]),
) as { readonly [name in RouteName]: string };

// The prefix every screen of one build shares. Not an address by itself: the
// router answers only the screens below it.
export const BUILD = "/products/:product/streams/:stream/variants/:variant";

export type Build = { product: string; stream: string; variant: string };

// Query parameters for an address. An undefined value is left out; an empty
// one is kept, because some screens tell a parameter set to nothing from one
// that is absent.
type Query = URLSearchParams | Record<string, string | undefined> | string | undefined;

// What picks one component among several of the same name.
type Which = { version?: string; ecosystem?: string; namespace?: string };

function withQuery(path: string, query?: Query): string {
  const asked = new URLSearchParams();
  if (typeof query === "string" || query instanceof URLSearchParams) {
    for (const [name, value] of new URLSearchParams(query)) asked.append(name, value);
  } else if (query) {
    for (const [name, value] of Object.entries(query)) {
      if (value !== undefined) asked.append(name, value);
    }
  }
  const rest = asked.toString();
  return rest ? `${path}?${rest}` : path;
}

// A pattern with each of its parts in place, escaped for a path segment.
function fill(pattern: string, parts: Record<string, string | number | undefined>): string {
  return pattern.replace(/:(\w+)/g, (_, name: string) =>
    encodeURIComponent(String(parts[name] ?? "")),
  );
}

const at = (
  name: RouteName,
  parts: Record<string, string | number | undefined> = {},
  query?: Query,
) => withQuery(fill(ROUTES[name], parts), query);

// One product and what hangs off it.
export const productAt = (product: string) => at("product", { product });
export const streamsAt = (product: string) => at("streams", { product });
export const streamAt = (product: string, stream: string) => at("stream", { product, stream });
export const variantsAt = (product: string) => at("variants", { product });
export const comparisonAt = (product: string, query?: Query) =>
  at("comparison", { product }, query);
export const inventoryComparisonAt = (product: string, query?: Query) =>
  at("inventoryComparison", { product }, query);
// A product's inbox, or only the rulings in it waiting for a second person.
export const inboxAt = (product: string, waiting = false) =>
  at("inbox", { product }, { waiting: waiting ? "1" : undefined });
export const inboxReportAt = (product: string, reference: string) =>
  at("inboxReport", { product, reference });

// A component of a product, wherever it sits. The version travels with it
// where it is known, and so does the build it was reached from, so the screen
// opens on the graph somebody was looking at rather than the first one.
export function componentAt(
  product: string,
  component: string,
  version?: string | null,
  from?: { stream?: string; variant?: string },
): string {
  return at(
    "productComponent",
    { product, component },
    {
      version: version || undefined,
      stream: from?.stream || undefined,
      variant: from?.variant || undefined,
    },
  );
}

// The findings list: across every product, one product's, and one build's.
export const allFindingsAt = (query?: Query) => at("findings", {}, query);
export const productFindingsAt = (product: string, query?: Query) =>
  at("productFindings", { product }, query);
export const buildFindingsAt = (build: Build, query?: Query) => at("buildFindings", build, query);

// The address a row of the findings list opens. The version is part of it: a
// component name is not unique within a build. It carries the list it came
// from so the finding can offer the row before and the row after. The list's
// address travels as one value rather than as its own parameters, so a filter
// added to the list needs nothing here and cannot collide with a name the
// finding screen already uses.
//
// Opened through a saved filter that prepares a claim, the filter's name
// travels too, and the finding fills its decision form from what that filter
// prepares. The name rather than the words: the filter is the one place
// deciding what it says, and a copy in an address is a second one that goes
// stale the moment somebody saves over the name.
export function findingAt(
  build: Build,
  row: {
    vulnerability?: string | null;
    component?: string | null;
    version?: string | null;
    ecosystem?: string | null;
    namespace?: string | null;
  },
  from?: string,
  rule?: string,
): string {
  return at(
    "finding",
    { ...build, vulnerability: row.vulnerability ?? "", component: row.component ?? "" },
    {
      version: row.version || undefined,
      // A name at a version can be two components in one build, so the
      // address carries the rest of what picks the row it was drawn from.
      ecosystem: row.ecosystem || undefined,
      namespace: row.namespace || undefined,
      rule: rule || undefined,
      // Set even when it is empty, because an unfiltered list is still a list:
      // the finding tells "there was no list" from "the list asked for
      // everything" by whether the parameter is there at all.
      from,
    },
  );
}

// The screens of one build.
export const treeAt = (build: Build, query?: Query) => at("tree", build, query);
export const decideAt = (build: Build, component: string, which: Which = {}) =>
  at(
    "decide",
    { ...build, component },
    {
      version: which.version || undefined,
      ecosystem: which.ecosystem || undefined,
      namespace: which.namespace || undefined,
    },
  );
export const inventoriesAt = (build: Build) => at("inventories", build);
export const inventoryChangesAt = (build: Build, scan: number) =>
  at("inventoryChanges", { ...build, scan });
export const runAt = (build: Build, run: number) => at("run", { ...build, run });
export const upgradesAt = (build: Build) => at("upgrades", build);
export const matchCoverageAt = (build: Build) => at("matchCoverage", build);
export const vexAt = (build: Build) => at("vex", build);

// A build's screen named by what follows the build in an address, for moving
// from one build to another and staying on the same screen. Nothing following
// it is the build's findings list.
export function sameScreenAt(build: Build, rest: string): string {
  const prefix = fill(BUILD, build);
  return rest ? `${prefix}/${rest}` : buildFindingsAt(build);
}

// A product's screen named by what follows the product in an address, for
// moving to another product and staying on the same screen.
export const sameProductScreenAt = (product: string, rest: string) => productAt(product) + rest;

// One thing, by what names it.
export const claimAt = (id: number) => at("claim", { id });
export const decisionAt = (id: number) => at("decision", { id });
export const issueAt = (vulnerability: string) => at("issue", { vulnerability });
export const personAt = (identity: string) => at("person", { identity });
export const advisoryAt = (advisory: string | number) => at("advisory", { advisory });
export const reportAt = (report: string) => at("report", { report });
export const settingsAt = (section: string) => at("settingsSection", { section });

// The review queue, for one product, on one of its lists, or opened on the
// claims somebody made themselves or has to re-affirm.
export const reviewQueueAt = (
  which: {
    product?: string;
    mine?: boolean;
    reaffirm?: boolean;
    reason?: "expired-deferral" | "missed-fix-date";
  } = {},
) =>
  at(
    "reviewQueue",
    {},
    {
      product: which.product || undefined,
      mine: which.mine ? "1" : undefined,
      reaffirm: which.reaffirm ? "1" : undefined,
      reason: which.reason,
    },
  );

// The form that records a flaw in a product, started from a report where one
// prompted it, or with where it came from already answered.
export const recordAt = (product: string, from?: string, source?: "outside") =>
  at("record", {}, { product, from: from || undefined, source });

// The Exploited here shelf, narrowed to one product where one is named.
export const obligationsAt = (product?: string) =>
  at("obligations", {}, { product: product || undefined });

// The record of judgments, asked a question.
export const auditAt = (query?: Query) => at("audit", {}, query);

// An address built here, with its query replaced, for a list moved to another
// scope with the filters it carried.
export function requeried(address: string, query: URLSearchParams): string {
  const cut = address.indexOf("?");
  return withQuery(cut < 0 ? address : address.slice(0, cut), query);
}

// The same address with one issue's name in place of another, where a screen
// is reached by a name that no longer files what it shows.
export function refiled(pathname: string, from: string, to: string): string {
  return pathname.replace(`/${encodeURIComponent(from)}`, `/${encodeURIComponent(to)}`);
}
