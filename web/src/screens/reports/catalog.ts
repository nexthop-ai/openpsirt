// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { type Scoped } from "../../app/scope";
import {
  auditAt,
  comparisonAt,
  inventoriesAt,
  matchCoverageAt,
  reportAt,
  streamsAt,
  type Build,
  upgradesAt,
} from "../../app/routes";

// The named reports, and where each is read.
//
// A report is a question somebody asks often enough to have a name. The
// catalog is the list of those names, grouped by what they answer; anything
// else is built on the findings list and its filters, which is the entry at
// the foot of the catalog screen.
//
// A report about the thing you are standing on lives on that screen and is
// listed here. A report that spans things lives only here. So a comparison
// of two releases keeps the address it has — it is the screen where the two
// are picked — and appears in the catalog with the selection already made,
// rather than being rebuilt as a second copy under a reports address.
//
// One address is one entry. Two names over the same screen read as two
// reports, and the reader opens both to find the same page.

// The level of the selection a scoped entry needs before it can answer.
export type Needs = "product" | "build";

export type Report = {
  // The last segment of the address, for a report the catalog owns. An entry
  // pointing at a screen of its own has none.
  slug?: string;
  name: string;
  // The question it answers, in one line.
  answers: string;
  // The address it is read at. A report the catalog owns is at its slug; one
  // that points elsewhere builds its address from the selection, so the scope
  // picker is not asked for twice.
  to?: (at: Scoped) => string;
  // What it needs picked, for a report that cannot span.
  needs?: Needs;
};

type Group = { name: string; reports: Report[] };

// withProduct carries the selection into an address that reads its narrowing
// from the address rather than from the picker.
//
// The record is the one screen that does: it is read as a document and sent as
// a link, so what it answers has to be in the address it was sent as.
function withProduct(asked: string, scope: Scoped): string {
  const query = new URLSearchParams(asked);
  if (scope.product) query.set("product", scope.product);
  return auditAt(query);
}

// The reports, by the question they answer. An entry leading to a filter on
// the record sits with the reports asking the same question, because the
// question is what somebody looks for it by.
export const GROUPS: Group[] = [
  {
    name: "Program",
    reports: [
      {
        slug: "program-overview",
        name: "Program overview",
        answers:
          "What is being fixed, what is aging, how long triage takes, and what keeps being put off.",
      },
      {
        slug: "backlog-over-time",
        name: "Backlog over time",
        answers:
          "Whether the backlog is growing: what arrived, what was answered, and what stood open.",
      },
      {
        slug: "deadline-compliance",
        name: "Deadline compliance",
        answers:
          "Whether work met its policy deadlines, by severity, with deliberate deferrals kept apart.",
        // A rate has to be about one product's policy.
        needs: "product",
      },
      {
        slug: "effort-by-component",
        name: "Effort by component",
        answers:
          "What the judgments in a period were about, most argued first, and what came of them.",
      },
    ],
  },
  {
    name: "Controls",
    reports: [
      {
        slug: "approval-quality",
        name: "Approval quality",
        answers:
          "How much the second person did: risk on one person, approver pairs, bulk agreements, grown coverage.",
      },
      {
        // The record answering the one question it was built to answer, with
        // the filters already set. REQ-53 names it as the report that should
        // come back empty, and the record's own empty state is written as that
        // answer.
        name: "The exception report",
        answers: "Dismissals with no standing agreement from a second person. Should be empty.",
        // The product the catalog is being read for, carried into the record.
        // The record reads its narrowing from the address alone, and without
        // the product it answers for every product the reader can see.
        to: (at) =>
          withProduct(
            "alone=true&outcome=not-applicable&outcome=mismatched&outcome=wont-fix" +
              "&outcome=already-fixed",
            at,
          ),
      },
      {
        // The record again, asked the other question it was built to answer.
        // Every other judgment lapses when the code moves; these do not, so
        // nothing brings them back round to anybody and the only way to read
        // them is to ask for them.
        name: "Standing corrections",
        answers: "Matches recorded as wrong that still stand, with who proposed and who agreed.",
        to: (at) => withProduct("in_force=true&outcome=mismatched", at),
      },
      {
        name: "Administrative changes",
        answers:
          "Changes to roles, support dates and thresholds. In the record, for administrators.",
        to: (at) => withProduct("", at),
      },
    ],
  },
  {
    name: "Coverage",
    reports: [
      {
        slug: "scan-coverage",
        name: "Scan coverage",
        answers: "What is being scanned, when each build was last seen, and what has gone quiet.",
      },
      {
        name: "Match coverage",
        answers: "Components in a build the scanner can't match, and why. They report no findings.",
        to: (at) => matchCoverageAt(buildOf(at)),
        needs: "build",
      },
      {
        name: "Carried patches",
        answers: "Fixes a distribution carries without changing the version. On the inventories.",
        to: (at) => inventoriesAt(buildOf(at)),
        needs: "build",
      },
    ],
  },
  {
    name: "Releases",
    reports: [
      {
        // The comparison screen, which also carries the known issues a build
        // ships with as its third column: one screen, so one entry.
        name: "Release comparison",
        answers: "Fixed, new and still present between two builds, and what stands about each.",
        to: (at) => comparisonAt(at.product ?? ""),
        needs: "product",
      },
      {
        name: "Release readiness",
        answers: "A branch against the last release cut from it. On the branches and tags list.",
        to: (at) => streamsAt(at.product ?? ""),
        needs: "product",
      },
      {
        slug: "releases-out-of-support",
        name: "Releases out of support",
        answers: "Releases past end of life that still ship, and what is open on them.",
      },
    ],
  },
  {
    name: "Records",
    reports: [
      {
        slug: "disposition-register",
        name: "Disposition register",
        answers: "Every vulnerability known in one build and what became of it, decided or not.",
        needs: "build",
      },
      {
        slug: "advisories-issued",
        name: "Advisories issued",
        answers: "What was published about flaws in our own product, and what went out twice.",
      },
    ],
  },
];

// Screens on the rail that answer a question with a name. Listed so the name
// finds them, apart from the reports, because each is a screen somebody
// already works in rather than a sheet to read; named as the rail names them.
export const ON_SCREENS: Report[] = [
  {
    // The assignments screen answers holder workload exactly, per person and
    // per team, with the overdue count beside the total.
    name: "Assignments",
    answers: "Work held per person and team, and how much of it is overdue.",
    to: () => "/work",
  },
  {
    name: "Disclosing",
    answers: "Embargoes running out, and what has to be said before they do.",
    to: () => "/disclosing",
  },
  {
    name: "Pending upgrades",
    answers: "The upgrades promised for a build, what they would close, and which have landed.",
    to: (at) => upgradesAt(buildOf(at)),
    needs: "build",
  },
];

// The whole build a selection names, for an entry that points at one of its
// screens.
function buildOf(at: Scoped): Build {
  return { product: at.product ?? "", stream: at.stream ?? "", variant: at.variant ?? "" };
}

// What a selection is missing for an entry, or null where it holds enough.
//
// A build is all three levels. The screens a build-scoped entry points at
// exist for one build and no other, and an entry into one on a partial
// selection would open on a scope that means nothing.
function lacks(needs: Needs | undefined, at: Scoped): Needs | null {
  if (needs === "product") return at.product ? null : "product";
  if (needs === "build") return at.product && at.stream && at.variant ? null : "build";
  return null;
}

// The destination of a catalog row, and what stands in the way.
//
// Returned together because a row that cannot answer is still worth drawing:
// a report missing from a list reads as a report that does not exist, and
// what somebody needs is to be told what to pick.
export function leadsTo(report: Report, at: Scoped): { to: string | null; needs: Needs | null } {
  const needs = lacks(report.needs, at);
  if (needs) return { to: null, needs };
  if (report.slug) return { to: reportAt(report.slug), needs: null };
  return { to: report.to?.(at) ?? null, needs: null };
}

// The subject a report answers for, as words. Every report states it, because a
// figure narrowed to one variant and a figure spanning a program are the same
// figure with very different meanings, and a printed sheet has nothing else to
// say which of the two it holds.
export function scopeWords(at: Scoped): string {
  return [
    at.product ?? "Every product",
    at.stream ?? "every branch",
    at.variant ?? "every variant",
  ].join(" · ");
}
