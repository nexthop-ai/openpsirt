// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { matchPath } from "react-router-dom";
import type { Body } from "../api/client";
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
export const BUILD = "/products/:product/branches-and-tags/:branch_or_tag/variants/:variant";

export type Build = { product: string; branch_or_tag: string; variant: string };

// The kinds of upload a build's Uploads screen has a tab for, in the server's
// own words.
export type UploadType = Body<"UploadKindBody">["type"];

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
export const branchesAndTagsAt = (product: string) => at("branchesAndTags", { product });
export const branchOrTagAt = (product: string, branchOrTag: string) =>
  at("branchOrTag", { product, branch_or_tag: branchOrTag });
// The place under a product's branches and tags that an address under its
// former streams prefix names. The rest arrives escaped, as the address had it.
export const fromStreamsAt = (product: string, rest: string) =>
  rest ? `${branchesAndTagsAt(product)}/${rest}` : branchesAndTagsAt(product);
export const variantsAt = (product: string) => at("variants", { product });
export const comparisonAt = (product: string, query?: Query) =>
  at("comparison", { product }, query);
export const inventoryComparisonAt = (product: string, query?: Query) =>
  at("inventoryComparison", { product }, query);
// A product's vulnerability reports, or only the rulings waiting for a second
// person.
export const vulnerabilityReportsAt = (product: string, waiting = false) =>
  at("vulnerabilityReports", { product }, { waiting: waiting ? "1" : undefined });
export const vulnerabilityReportAt = (product: string, reference: string) =>
  at("vulnerabilityReport", { product, reference });
// A product's static analysis code findings: the queue, or one state's code findings, on
// every build or one.
export const codeFindingsAt = (
  product: string,
  query?: {
    state?: string;
    branch_or_tag?: string;
    variant?: string;
    series?: string;
    method?: string;
    assigned?: "nobody";
    component?: string;
    component_version?: string;
    beneath?: string;
    beneath_version?: string;
    beneath_ecosystem?: string;
    beneath_namespace?: string;
  },
) => at("codeFindings", { product }, query);
// One code finding's evidence on one build.
export const codeFindingAt = (build: Build, occurrence: string) =>
  at("codeFinding", { ...build, occurrence });
// The suppression rules dismissing a product's code findings.
export const suppressionRulesAt = (product: string) => at("suppressionRules", { product });
// The hosts a product's source links open on, and what it says per path.
export const repositoriesAt = (product: string) => at("repositories", { product });
// The components a term names, in the picker's selection.
export const componentSearchAt = (term: string) => at("componentSearch", { term });

// A component of a product, wherever it sits. The version travels with it
// where it is known, and so does the build it was reached from, so the screen
// opens on the graph somebody was looking at rather than the first one.
export function componentAt(
  product: string,
  component: string,
  version?: string | null,
  from?: { branch_or_tag?: string; variant?: string },
): string {
  return at(
    "productComponent",
    { product, component },
    {
      version: version || undefined,
      branch_or_tag: from?.branch_or_tag || undefined,
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
// Opened through a saved filter that prepares a decision, the filter's name
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
    { ...build, issue: row.vulnerability ?? "", component: row.component ?? "" },
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

// The finding a row names when it carries its build beside the rest, as the
// queue's rows do: one record holding all of it, each part possibly absent.
export function findingOf(row: {
  product?: string | null;
  branch_or_tag?: string | null;
  variant?: string | null;
  vulnerability?: string | null;
  component?: string | null;
  version?: string | null;
  ecosystem?: string | null;
  namespace?: string | null;
}): string {
  return findingAt(
    {
      product: row.product ?? "",
      branch_or_tag: row.branch_or_tag ?? "",
      variant: row.variant ?? "",
    },
    row,
  );
}

// The screens of one build.
export const dependenciesAt = (build: Build, query?: Query) => at("dependencies", build, query);
export const bulkDecisionAt = (build: Build, component: string, which: Which = {}) =>
  at(
    "bulkDecision",
    { ...build, component },
    {
      version: which.version || undefined,
      ecosystem: which.ecosystem || undefined,
      namespace: which.namespace || undefined,
    },
  );
// A build's uploads, opened on one kind of upload where one is named.
export const uploadsAt = (build: Build, type?: UploadType) =>
  type && type !== "sbom" ? at("uploadsOf", { ...build, type }) : at("uploads", build);
export const inventoryChangesAt = (build: Build, scan: number) =>
  at("inventoryChanges", { ...build, sbom: scan });
export const runAt = (build: Build, run: number) => at("run", { ...build, run });
export const plannedUpgradesAt = (build: Build) => at("plannedUpgrades", build);
export const unmatchedComponentsAt = (build: Build) => at("unmatchedComponents", build);
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
export const decisionAt = (id: number) => at("decision", { id });
export const decisionOccurrenceAt = (id: number) => at("decisionOccurrence", { id });
export const issueAt = (issue: string) => at("issue", { issue });
export const personAt = (identity: string) => at("person", { identity });
export const advisoryAt = (advisory: string | number) => at("advisory", { advisory });
export const analyticsReportAt = (report: string) => at("analyticsReport", { report });
export const settingsAt = (section: string) => at("settingsSection", { section });

// The review queue, for one product, on one of its lists, or opened on the
// decisions somebody made themselves or has to re-affirm.
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
export const recordFlawAt = (product: string, from?: string, source?: "outside") =>
  at("recordFlaw", {}, { product, from: from || undefined, source });

// The Incidents screen, narrowed to one product where one is named.
export const incidentsAt = (product?: string) =>
  at("incidents", {}, { product: product || undefined });

// The audit log, asked a question.
export const auditLogAt = (query?: Query) => at("auditLog", {}, query);

// An address built here, with its query replaced, for a list moved to another
// scope with the filters it carried.
export function requeried(address: string, query: URLSearchParams): string {
  const cut = address.indexOf("?");
  return withQuery(cut < 0 ? address : address.slice(0, cut), query);
}

// The same address with one issue's name in place of another, where a screen
// is reached by a name that no longer files what it shows.
//
// Rebuilt from the route rather than substituted in the text, so a product,
// branch or component whose name begins with the issue's is left alone. A
// matched part arrives with only its escaped slashes decoded, so each is
// decoded whole before it is escaped again, or "libstdc++6" comes back as
// "libstdc%252B%252B6".
export function refiled(pathname: string, from: string, to: string): string {
  for (const name of ["finding", "issue"] as const) {
    const hit = matchPath(ROUTES[name], pathname);
    if (!hit) continue;
    const parts = Object.fromEntries(
      Object.entries(hit.params).map(([key, value]) => [key, decoded(value ?? "")]),
    );
    if (parts.issue === from) {
      return fill(ROUTES[name], { ...parts, issue: to });
    }
  }
  return pathname;
}

function decoded(part: string): string {
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}
