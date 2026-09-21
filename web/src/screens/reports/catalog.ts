import { type Scoped } from "../../app/scope";

// The named reports, and where each is read.
//
// A report is a question somebody asks often enough to have a name. The
// catalog is the list of those names; anything else is built on the findings
// list and its filters, which is the entry at the foot of the catalog screen.
//
// A report about the thing you are standing on lives on that screen and is
// listed here. A report that spans things lives only here. So a comparison
// of two releases keeps the address it has — it is the screen where the two
// are picked — and appears in the catalog with the selection already made,
// rather than being rebuilt as a second copy under a reports address.

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
  // The picks it needs before it can answer anything, for a report that
  // cannot span.
  needs?: (at: Scoped) => string | null;
};

// withProduct carries the selection into an address that reads its narrowing
// from the address rather than from the picker.
//
// The record is the one screen that does: it is read as a document and sent as
// a link, so what it answers has to be in the address it was sent as.
function withProduct(at: string, scope: Scoped): string {
  if (!scope.product) return at;
  const joined = at.includes("?") ? "&" : "?";
  return `${at}${joined}product=${encodeURIComponent(scope.product)}`;
}

export const CATALOG: Report[] = [
  {
    slug: "program-overview",
    name: "Program overview",
    answers:
      "How the work is going: what is being fixed, what is aging, how long triage takes, what keeps being put off, and what has been argued away.",
  },
  {
    slug: "scan-coverage",
    name: "Scan coverage",
    answers:
      "What is being scanned, when each build was last seen, and what has quietly stopped. Every other number is worthless if a build stopped being scanned, and silence looks exactly like health.",
  },
  {
    slug: "releases-out-of-support",
    name: "Releases out of support",
    answers:
      "What is still shipped and no longer maintained. Past end-of-life the deadline comes off every open finding, so this pile is absent from every overdue count by design.",
  },
  {
    slug: "backlog-over-time",
    name: "Backlog over time",
    answers:
      "Whether the backlog is growing, and what kind of thing is making it grow: what arrived, what was answered, and what stood open, each split by severity.",
  },
  {
    slug: "rubber-stamp",
    name: "Rubber-stamp",
    answers:
      "How much a second pair of eyes actually did: what stands on one person, who agrees with whom, what was agreed in bulk, and what covers more now than when somebody agreed to it.",
  },
  {
    slug: "where-the-effort-went",
    name: "The destination of the effort",
    answers:
      "What the judgments in a period were about, most argued first: which component, how many arguments, how far they reached, and what came out of them. Every other report counts the backlog; this one says what the quarter went into.",
  },
  {
    slug: "deadline-compliance",
    name: "Deadline compliance",
    answers:
      "Whether work met the dates policy set for it, by severity, with what was deferred deliberately kept apart from what is plainly late.",
    needs: (at) => (at.product ? null : "Pick a product: a rate has to be about one."),
  },
  {
    slug: "disposition-register",
    name: "Disposition register",
    answers:
      "Every vulnerability known in one build and what became of it, decided or not, with no triage line applied. The complement of the record: that says what was decided, this says what was known.",
    needs: whole,
  },
  {
    slug: "advisories-issued",
    name: "Advisories issued",
    answers:
      "What has been published about flaws in our own product, and what was published twice. Answered per flaw elsewhere; this is the question a period asks.",
  },
  {
    name: "Release readiness",
    answers:
      "Whether a branch is ready to cut, against the last release cut from it. On the branches list, where the two are picked.",
    to: (at) => `/products/${encodeURIComponent(at.product ?? "")}/streams`,
    needs: (at) => (at.product ? null : "Pick a product to see its branches and tags."),
  },
  {
    name: "Upgrade plan status",
    answers:
      "What each build is waiting on: the upgrades promised, what they would close, and which have landed.",
    to: (at) => `${buildAt(at)}/pending-upgrades`,
    needs: whole,
  },
  {
    name: "Carried patches",
    answers:
      "What a distribution fixed without moving the version, which no comparison of versions can see. On the build's inventories screen.",
    to: (at) => `${buildAt(at)}/scans`,
    needs: whole,
  },
  {
    // Not a page of its own: the assignments screen already answers exactly
    // this, per person and per team, with the overdue count beside the total.
    name: "Holder workload",
    answers:
      "How much work each person and team is carrying, and how much of it is past its deadline. An idle account holding nothing is harmless; the overdue count is what separates keeping up from sitting on it.",
    to: () => "/work",
  },
  {
    name: "Embargo and disclosure",
    answers: "What is running out of embargo, and what has to be said about it before it is.",
    to: () => "/disclosing",
  },
  {
    // The record answering the one question it was built to answer, with the
    // filters already set. REQ-53 names it as the report that should come
    // back empty, and the record's own empty state is written as that answer.
    name: "The exception report",
    answers:
      "Dismissals no second person has a standing agreement on. It should come back empty — every dismissal requires one, so a row here is a control that did not hold.",
    // The product the catalog is being read for, carried into the record. The
    // record reads its narrowing from the address alone, so an entry that
    // dropped it opened every product the reader can see from a page scoped
    // to one — a different population under the same name.
    to: (at) =>
      withProduct(
        "/audit?alone=true&outcome=not-applicable&outcome=mismatched&outcome=wont-fix" +
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
    answers:
      "The matches recorded as wrong, and still standing: what each is about, who proposed it, who agreed, and on what grounds. Nothing expires one, so this is the list nobody is shown unless they ask.",
    to: (at) => withProduct("/audit?in_force=true&outcome=mismatched", at),
  },
  {
    name: "Administrative changes",
    answers:
      "Who moved the ground under the judgments: roles, support dates, thresholds. In the record, for administrators.",
    to: (at) => withProduct("/audit", at),
  },
  {
    // The sign-off sheet. The comparison screen already answers it, so the
    // catalog carries it with the selection made rather than a second page
    // being built over the same query.
    name: "Shipping with known issues",
    answers:
      "What a build still carries, with what stands about each: agreed and why, waiting on a second person, or nobody has said anything. The last of those is the release coordinator's blocker list.",
    to: (at) => `/products/${encodeURIComponent(at.product ?? "")}/comparison`,
    needs: (at) => (at.product ? null : "Pick a product to compare two of its builds."),
  },
  {
    name: "Release comparison",
    answers:
      "What changed between two builds — fixed, newly present, and still present — in the form a release note takes.",
    to: (at) => `/products/${encodeURIComponent(at.product ?? "")}/comparison`,
    needs: (at) => (at.product ? null : "Pick a product to compare two of its builds."),
  },
];

// The address of a whole build, for an entry that points at one of its screens.
function buildAt(at: Scoped): string {
  return (
    `/products/${encodeURIComponent(at.product ?? "")}` +
    `/streams/${encodeURIComponent(at.stream ?? "")}` +
    `/variants/${encodeURIComponent(at.variant ?? "")}`
  );
}

// The picks a build-scoped entry needs. Five screens exist for one build and no
// other, and an entry into one of them without a build picked would open on a
// scope that means nothing.
function whole(at: Scoped): string | null {
  if (at.product && at.stream && at.variant) return null;
  return "Pick a product, a branch or tag, and a variant: this is about one build.";
}

// The report at an address, or nothing where the catalog has no such name.
export function reportAt(slug: string): Report | undefined {
  return CATALOG.find((report) => report.slug === slug);
}

// The destination of a catalog row, and what stands in the way.
//
// Returned together because a row that cannot answer is still worth drawing:
// a report missing from a list reads as a report that does not exist, and
// what somebody needs is the sentence saying which picker to touch.
export function leadsTo(report: Report, at: Scoped): { to: string | null; why: string | null } {
  const why = report.needs?.(at) ?? null;
  if (why) return { to: null, why };
  if (report.slug) return { to: `/reports/${report.slug}`, why: null };
  return { to: report.to?.(at) ?? null, why: null };
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
