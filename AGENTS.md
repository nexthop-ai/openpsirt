# Agent instructions for OpenPSIRT

OpenPSIRT takes in the inventory a build produced, scans it for known
vulnerabilities here rather than in the build, tracks what changes release to
release, and gives people somewhere to triage findings and follow them through
to a fix. It is Apache 2.0, installed and run by other people (REQ-01 and REQ-10).

**Read `REQUIREMENTS.md` before proposing anything.** Most questions have already
been answered there, with the reasoning. If you think a decision is wrong, say
so and cite its ID — do not quietly implement something else.

## Document map

| File | Holds | Lifetime |
|---|---|---|
| `REQUIREMENTS.md` | **Why** — every decision, with reasoning, by area | Permanent |
| `DESIGN-*.md` | **How** — structures, flows, behavior | Permanent |
| `TODO.md` | **What is left** — not built, deferred, or waiting on a decision | Until it is empty |
| Code | What runs | — |

### The chain that makes audits possible

Code satisfies a design document. A design document names the decision IDs it
implements. A decision says why.

**If code does something no design document describes, it is a remnant.** Either
the design document is out of date or the code should not be there. Both get
re-examined; neither is assumed correct. This is the whole reason the design
documents exist, so keeping them current is part of the change, not follow-up
work.

**The other direction is checked by the gate.** `make check` fails on a
decision in force that no design document names. A decision that is not built
yet is not exempt — the document for its area says that it is not built, in
words, which is the difference between a plan somebody can read and a gap
somebody rediscovers by clicking. Naming a decision means describing it: adding
the identifier to a "Satisfies" line without writing what it does makes the
audit trail a lie, which is worse than the gap it was hiding.

**The gate cannot check that half, and does not pretend to.** It matches
identifiers rather than reading prose, so naming a decision anywhere in a
design document satisfies it, and a range — `REQ-23, REQ-24, REQ-25` — names all
three. A hundred and thirty-two of the decisions in force are claimed by a
range endpoint and nothing else, which is fine where the document describes
them without the identifier beside each one and a lie where it does not. Which
of those it is remains a person's judgment; the gate's guarantee is only that
nothing is claimed by nobody.

## Design documents

All at the repository root, named `DESIGN-<area>.md`.

- **Keep them language-agnostic.** They describe behavior, architecture and
 domain concepts — SBOM structure, dependency paths, triage outcomes,
 visibility rules. Never type names, struct fields, function signatures or
 source paths. Implementation pointers belong in code.
- **Name the decisions they satisfy**, by ID. That is the audit trail — and
 naming means describing: a `Satisfies` line citing an identifier the document
 never explains reads as an audit trail and is not.
- **A decision that is only a choice of tool is not named by a design
 document.** Which language, which router, which query builder, which chart
 library: describing those here is forbidden by the rule directly above, so
 requiring them to be named here asks for two things that cannot both be true.
 `REQUIREMENTS.md` is where each of those lives and the only place it needs to,
 and the gate carries the list. The test for adding one is narrow — the
 decision picks a tool and nothing else — because putting a decision about
 behavior on that list to quiet the gate is the failure the list exists to
 avoid.
- **Record what the decisions did not cover.** Plenty gets chosen while writing
 code that no decision anticipated. Those choices are exactly what an auditor
 cannot distinguish from an accident, so write them down.
- **Update them in the same change as the code.** A design document that lags is
 worse than none, because it is trusted and wrong.

### The Spec style

Every `DESIGN-*.md` is written in one style, called **Spec**. It is not a
preference. These documents were prose-heavy and unusable, and drifted back
that way twice; what follows is the shape they were pulled into.

| Rule | |
|---|---|
| **A heading is a noun phrase naming the mechanism** | Six words at most, no full stop, no question mark. "Incomplete upgrades", not "A bump that did not reach the fix" — the second withholds its subject to make somebody read on |
| **No lead-in sentences** | Open on the fact. "A decision is keyed on the product, the issue and the place", not "Nothing in what identifies a decision names the release it was made in — and that is deliberate" |
| **State rather than argue** | A design document records what was decided, not the case for it. The reason belongs beside the rule in a second column, one clause long, not woven through three paragraphs |
| **Bold marks a defined term, not a pressed claim** | Bolding the first half of every sentence is emphasis nobody reads by the third screen |
| **Enumerations are tables** | Outcomes, refusals, closure reasons, engine differences, settings, states. A two-column `\| rule \| why \|` table is the default shape of a section |
| **One fact in one place** | A fact another document owns is pointed at, not restated. Two copies disagree eventually and neither says which is authoritative |
| **Rationale that is not about one rule goes in `Limits`** | The block at the foot of every document, for the boundaries and the trade-offs the sections above would otherwise argue in line |
| **Every document opens with a `Contents` section** | One entry per `##` heading, in order |
| **Measured numbers stay** | "5,047 fixable rows are 271 distinct bumps" is evidence for a design choice. Cut the sentence introducing it, not the number |
| **Component selection is design** | Why this scanner, this database, this format is part of the document. Why a variable is named what it is, is not |

Two of those are checked by `internal/docs/style_test.go` — the heading bound
and the `Contents` list — because they are the two that regress silently. The
rest is judgment, and this is the whole of it.

**A section that has drifted reads a particular way**: paragraphs opening with
a bolded claim, the reason for a rule three sentences past the rule, and a
heading that is a sentence. Rewrite it rather than appending to it.

## What is left lives in one place

`TODO.md` holds everything still in scope and not built: the work that has to
happen before the first release, what the owner deferred, decisions taken but
not implemented, questions waiting on an answer, and what was measured and left
alone deliberately.

**Nothing may reference it** — not code, not comments, not commit messages, not
the design documents. It is a work list, not a record. Anything durable moves
to `REQUIREMENTS.md` or a `DESIGN-*.md` before it is ticked off.

Name regression tests for the invariant they pin, never for an item on a list.

## Non-negotiables

These are the decisions easiest to violate by accident, and most expensive to
unpick later.

| Rule | Decision |
|---|---|
| **No engine-specific SQL in the core.** Four engines are supported. Engine-specific code lives in the database package and the job queue's locking, and nowhere else — `DESIGN-database.md` lists every case and is the only list; do not count them in a second place | REQ-71 |
| **Never trust identifiers a scan file supplies** to be stable between builds or consistent between producers. Identity is derived from content | REQ-08 |
| **Visibility is enforced in the data-access layer**, never per handler, and every query carries a subject. This covers counts, aggregates, search and exports — not just row reads | REQ-42 and REQ-43 |
| **A finding is a component at a specific place.** Do not deduplicate up to the package. Grouping is presentation only | REQ-17 |
| **Identity is structural; expiry is version-based.** Never mix them — that is how an unrelated top-level bump invalidates a leaf decision | REQ-25 |
| **A test that pins what a query does runs on every supported engine.** SQLite-only tests catch none of the portability traps. A test that pins routing, which role reaches which endpoint, or a response's shape runs on SQLite and PostgreSQL, because nothing it pins varies by engine — the choice is made by reading the test, and it is the SQL that decides | REQ-71 |
| **Every transaction is retryable as a whole**, through the one helper. A cluster certifies at `COMMIT`, so a write whose statements all succeeded can still be rolled back under it | REQ-71 |
| **Nothing a transaction depends on is read outside it.** A retry re-runs the closure against a moved database, so a value fetched before it began describes a world that is gone. Anything the closure uses but does not fetch is a defect | REQ-71 |
| **SQL values are parameterized and SQL identifiers come from an allowlist.** A placeholder cannot bind a column name, so a sort column from a query parameter is the real risk | REQ-66 |
| **Every identifier is quoted, including the names a query invents.** A reserved word is only reserved when it is bare, and the four engines reserve different ones — `make reserved` checks every alias against what they actually reserve rather than against a list somebody remembered | REQ-71 |
| **An affected-row count means rows matched, not rows changed.** A conditional update reads it as "the row was still there", so a write whose values were already correct must not report zero — the connection settings make that true on all four engines | REQ-71 |
| **Exported code with no caller is a defect, not spare capacity.** A store method nothing routes to, a renderer nothing renders with. The separate check does look at exported symbols, but **it counts a test as a caller** — its own source says so — so a symbol only its own tests reach passes it, which is where most of them are | — |
| **A decision no design document names is a defect too.** Built or not, every decision in force is described somewhere permanent; the gate fails on one that is not. It found 71 the first time it ran, five of them cited by running code. **It counts a mention, not a description** — its own source says so — so an identifier appearing in a `Satisfies` line is all it asks for, and the rule above that naming means describing is a person's to enforce | — |
| **The gate checks that decisions have documents, never that the documents are true.** Nothing can: a paragraph describing behavior nobody wrote reads exactly like one describing behavior somebody did. A review found five — a format recorded as accepted that the code refuses, a secondary ingest path nothing reads, chat adapters written up as though they shipped, a decision claimed as built on one line and not built on another, and an alert described as behavior that nothing computed. **So a document is checked by reading the code against it, and that is a person's job**; where something is half built, say which half | — |
| **A test for a control is verified by breaking the control.** Watch it fail for the reason it names, then put the control back. A control whose test has never been seen to fail is a control nobody has tested | — |
| **A request is authorized before any name in it is resolved.** Resolving first and refusing after makes the refusal informative: a name nobody holds and a name somebody holds come back differently, which turns a lookup into a directory | REQ-42 |
| **Every setting offered is one something reads.** A value somebody sets that changes nothing is worse than not offering it, and zero or negative reads as unset everywhere — so those are refused rather than stored | — |
| **A name people type is matched without regard to capitals; an identity a provider hands over is matched exactly.** Normalize the stored value rather than asking an engine to compare loosely — the engines default differently, and a normalized value compares the same under any of them | REQ-08 |
| **Every identifier a query invents is quoted too**, and named around the reserved words. A derived table called `groups` is a syntax error on MySQL 8 and fine on the other three | REQ-71 |
| **Every identifier in the schema is quoted.** A reserved word is only reserved when bare, and the four engines do not agree on which words those are — an unquoted name fails on whichever engine somebody is least likely to be running | REQ-71 |

## Nothing is made faster until it is measured slow

**Work out an answer when it is asked for.** No caching, no precomputed
totals, no refresh job, no denormalized copy — until somebody has measured a
real deployment and found a real problem. A stale answer is a cost paid up
front for a benefit nobody has demonstrated, and it brings its own bugs:
invalidation, drift, and a number that is wrong in a way nothing reports.

This is worth stating because the pressure is always toward the opposite. A
mature tool nearby stores metric snapshots and refreshes them hourly, and
copying that looked like prudence rather than what it was — adopting somebody
else's constraints, from a hosted product with traffic this one will not see.

**Storing a derived value to be correct is a different thing.** Some values
cannot be worked out again later at all, because the moment they describe is
gone. What a place held before a version moved is recorded as the scan applies,
because that is the only point at which both versions are in hand. How many
builds an approval reached is recorded as granted, because what the record needs
is what somebody agreed to rather than what the matching rules would say today.
Those are facts about a moment, stored for the same reason a scan's provenance
is.

**A value that can still be worked out is not one of those, and storing it does
not freeze it.** A finding's urgency is stored so that a list can sort on it
without joining four signals for every row on every page — that is speed, and it
earns its place — and it is rewritten when the signals move, because it
describes an issue rather than a moment (REQ-32). Reading "stored" as "frozen"
is what left urgency as three policies at once, none of them chosen. The test is
what the storing is *for*: correctness keeps it, speed has to earn it, and
neither buys the right to go stale.

## Two limits that erode if they are not rules

**A short-bump flag is inequality, never ordering.** Saying "this moved and is
still not the version that fixes it" needs no version comparison. Adding one is
a different project — per-ecosystem ordering for Debian epochs, RPM release
segments, semantic versions and the ecosystems that follow none of them — and
it buys a sharper sentence rather than a new signal. One "just add a compare
function" is all it takes (REQ-21).

**A bulk write is bounded.** One action recording a judgment against many
issues is deliberate and useful; one action writing an unbounded number of rows
is a denial of service somebody triggers by accident. The cap is a setting, not
a constant, and there is always a cap (REQ-27).

**Bound what is written, not what was asked for.** The two differ whenever one
named thing expands into many rows — an issue sits at many places — so a limit
checked against the request lets a small request do a large amount of work
(REQ-27).

## Source file size

**Target about 1200 lines per source file.** A point to split at, not a hard
limit.

A file past it is usually doing more than one thing. The cost is not storage —
it is that nobody reads to the end, changes get made in the wrong place, and
review gets shallower the further down the diff it goes.

Split by **responsibility, not by line count**. Cutting a coherent file in half
to hit a number makes it worse, and a 1300-line file that genuinely does one
thing is better left alone than split badly. Act on the trend rather than the
threshold: splitting late is far more work than splitting early.

Documentation is not governed by this. A design document is as long as its
subject, and splits when it covers two subjects rather than when it reaches a
length.

## Decision identifiers

**Keep rows sorted by identifier within each table.** Adding a decision next to
a related one is the natural instinct and it scrambles the order — which makes a
reference document hard to scan and makes it look like entries are missing.
Append, sort, and use a cross-reference to point at the related decision.

Identifiers never change. Renumbering breaks every commit message and design
document that cites one.

## Nothing is compatible with anything yet

Before the first release there is no schema compatibility and no API
compatibility. A schema change **edits the migration that created the thing**
rather than adding one beside it, and anybody holding a development database
recreates it. The version in the API path is the shape it will have, not a
promise anybody may hold us to.

The migrations that exist are kept only because walking the chain up and down
catches an ordering mistake between them. They collapse into one before release
(REQ-72), which `TODO.md` records so it happens rather than being remembered.

## Decisions carry the evidence that forced them

**Where a decision was settled by a measurement, the measurement goes in the
justification.** Not "the fan-out is large" but "335,021 findings for one
image, 305,487 of them a single kernel across 62 modules". Not "walking is
cheap" but "3 ms on PostgreSQL, 11 ms on MySQL, for the worst component in a
real graph".

A number is checkable and a judgment is not. Somebody reading this in two
years can re-run the measurement and see whether it still holds, which is the
difference between a decision that can be revisited and one that has to be
taken on trust. It is also the honest record of *why now* — several of these
were held open specifically until there was something real to measure.

The same applies to a reversal: what was believed, what was measured, and which
of the two was wrong.

## Code conventions

**No implementation-timeline language in code or comments.** Never write "for
now", "temporarily", "first cut", "later", "in this phase", "step N", or
anything describing *when* in the build something happens. Such notes rot the
moment the next change lands. Comment the current behavior and why. If
something genuinely is missing, describe the missing behavior or the
limitation — not when it will arrive.

**No ticket or tracker references in code, comments or documents.** A bare
number is unactionable at the code and rots as work is split or superseded.
Describe the behavior, reason or limitation instead, and keep issue linkage in
the tracker and the pull request.

**Comment density matches the surrounding code.** Explain why, not what.

**API descriptions are reference documentation, not prose.** A summary is an
imperative verb and the thing it acts on, in the words the domain actually uses
— "Upload an SBOM", "List vulnerability findings", "Approve a triage decision".
Not "Send what a build shipped", "What is open against a build", "Agree to a
claim": somebody scanning thirty operations has to find theirs in a second, and
paraphrase that avoids naming the thing reads as a riddle.

A description says what the operation does, what it takes, what comes back, and
what a caller must know that is not obvious — a 202 that returns before
parsing, a field required only for one outcome, an approval that a later edit
withdraws. **The reasoning belongs in `REQUIREMENTS.md` and the design documents,
not here.** Somebody reading the API reference is trying to make a request
work, and an explanation of why the design is what it is stands between them
and that.

**The mechanical half of that is a gate; the rest is judgment.** A test walks
the document the server builds and fails a missing summary or description, a
summary shaped like one of the counter-examples above, a summary written as a
sentence rather than a label, an operation that says nothing about what it
requires, and a decision identifier anywhere in either — which names a file
nobody outside this repository has. Whether a paragraph is an explanation of
the design or a thing a caller has to know is not checkable and stays a
person's to decide.

**American spelling, everywhere.** License, not licence. Catalog, normalize,
behavior, color, authorize. It applies to prose, comments and identifiers
alike — a codebase that spells one word two ways makes both unsearchable, and
the choice matters less than the consistency.

Two things are exempt because they are not ours to respell: text quoted from a
producer's output, and field names defined by a format we consume.

**No contractions in anything durable.** The design documents have none and
`REQUIREMENTS.md` had thirty-one, which is the same document at a different
register — and a decision is read years later by somebody deciding whether it
still holds. It is not a rule about formality: an expanded "does not" is one
word harder to misread than "doesn't" in a sentence that is already carrying a
negation. Temporary documents and commit messages are exempt.

**The name is written OpenPSIRT.** In prose and in anything a person reads —
documentation, the API description, the version the binary prints, a chart
description. It is a product name, and a product name that appears in three
casings reads like three different things.

Lower case is for what someone types or a machine matches: the command
(`openpsirt migrate up`), the module path, the container image, the chart, the
`OPENPSIRT_` environment prefix, and paths like `cmd/openpsirt/`. Those are
identifiers rather than the name, and changing them would break what people
already have.

## Security review checklist

Worked through on every review (REQ-75). Each line says what to look for **in this
codebase**, not in general — a checklist that restates the category is one that
gets ticked without being read.

| Category | Check |
|---|---|
| **Injection — SQL** | Every value parameterized. **Every identifier from an allowlist** — a sort column and a filter field cannot be bound by a placeholder, so a column name arriving from a query parameter is the live hole (REQ-66). Nothing is partitioned, so there are no partition names to guard; `DESIGN-database.md` says what is not built there |
| **Injection — output** | Component names, versions and descriptions come from a third party's SBOM and get rendered to staff who hold the most access. Encoded on output, and **never passed through the markdown renderer** — that is for text a person typed here (REQ-66). **A URL from a scan or a feed is not encoded output**: it is a scheme a browser acts on, so it is allowlisted before it becomes somewhere to click, and shown without a link where it fails |
| **Injection — markdown** | Policy enforced at submission, **before storage**: raw HTML off at the parser rather than stripped after, link schemes limited to `http`, `https`, `mailto` — a destination beginning `//` or `/\` is an address on another host, not a relative link — and **nothing remote fetched by a rendered document, images included**. Source stored, never rendered HTML. **Nothing on the server renders**, so sanitizing runs wherever the text is rendered: the interface for a browser, an integrator for their own application, and what the submission check does not catch is theirs to catch. **The fenced-block language tag is input** — allowlisted before it reaches a class attribute, by the renderer, which is where the class is written (REQ-67) |
| **Broken access control** | Enforced in the data layer with a subject, never per handler. Covers counts, aggregates, search and exports — not just row reads (REQ-42 and REQ-43). An attachment fetch is authorized against its finding's visibility before any signed URL is issued (REQ-70) |
| **Cryptographic failures** | API keys and personal tokens hashed at rest, shown once (REQ-68). Session identifiers unguessable |
| **Insecure design** | Does the change contradict a recorded decision? Cite the identifier if so |
| **Security misconfiguration** | Container non-root with a read-only root filesystem. Trusted-header sign-in off by default and only from configured sources (REQ-41) |
| **Vulnerable components** | `govulncheck` and dependency review gate. A new dependency needs a permissive license (REQ-01) |
| **Authentication failures** | No account created for anybody nothing authorized in advance. In group-bound mode the mapping an administrator made *is* that authorization, so a record is written on first arrival for somebody it covers and nobody else — every other path refuses an unknown arrival outright. Unauthorized users get a generic message that does not say why (REQ-41) |
| **Data integrity** | A scan file is hostile input. Bounded size, depth and component count; never used as a filesystem path (REQ-66 and REQ-69). Markdown fields are length-bounded and rendering is time-bounded (REQ-69) |
| **Separation of duties** | An approval points at one revision of a justification. Anything that lets approved text change without withdrawing the approval defeats REQ-24 silently (REQ-28) |
| **Logging failures** | Secrets never logged. Triage actions land in the append-only history (REQ-68) |
| **Request forgery** | Outbound fetches restricted to their configured host, no redirects into private address space (REQ-69) |

## Testing

- Every change runs against all four database engines in CI.
- Test fixtures include a real SBOM per supported producer, plus one full-size
 fixture for performance work.
- **Authorization is tested as a matrix**: role × visibility × endpoint,
 including counts, aggregates, search and exports.
- Regression tests are named for the invariant they pin.

## Commits and pull requests

- **No `Co-Authored-By` trailers.** This project will use DCO, where the only
 trailer that carries meaning is `Signed-off-by`. A co-author trailer asserts
 authorship that nobody has signed for, and mixing the two makes the sign-off
 chain ambiguous. Tools that add one by default must be told not to.

 **This holds from the root commit.** It did not hold before: of the last four
 hundred commits of the history this repository was imported from, seventy-nine
 carried a co-author trailer added by tooling that was not told not to, and
 thirteen carried one with no sign-off at all. That history was not brought
 across, so there is nothing left to unpick — which leaves the tooling as the
 only thing that can put one back. Tell it not to.
- Explain **why** in the body. The diff already shows what.
- Design document updates belong in the same commit as the behavior they
 describe.
- **Every change reaches `main` through a pull request and the merge queue.**
 Nothing is pushed to `main` directly, including by an administrator.
- **One check is required: `Merge Status`.** It is an aggregator — it waits for
 every other check on the commit to pass or be skipped, so a workflow added
 later gates a merge without anybody editing the ruleset. What that costs is
 stated where it is defined: a workflow contributing no check run on the event
 cannot be distinguished from one that has not started, so **every workflow
 meant to gate a merge declares `merge_group:` alongside `pull_request:`**.

### Development workflow

**Commit and push as work lands. Never leave finished work sitting in a working
tree.** A working tree is one disk, one machine and one accident away from
being gone; a pushed commit is not. So a stretch of work ends with a commit
and a push, and a long stretch is committed in purposeful pieces along the
way — a decision recorded, a behavior built with its design document, a
screen rebuilt — each with a body that says why.

**Never force-push.** As long as history is only ever added to, everything is
recoverable, and a mistake is fixed by a commit on top rather than by
rewriting what somebody else may already have pulled.

**Where it goes.** A branch, and a pull request from it. The work is pushed as
it lands and the pull request is where it is reviewed; the queue is what puts
it on `main`. The gate runs before the push regardless of what CI will do
afterwards: `make gate` for a commit, `make gate full` for a push carrying
more than one. Waiting for CI to find what one command here finds in minutes
is how a queue fills with entries that were never going to merge.

**The history starts at the import.** What came before it was development
against a single working copy, and it was not carried across — so `main` has
one root commit and every commit after it arrived through a pull request. The
reasoning that history would have held is not lost, because this project does
not keep it there: `REQUIREMENTS.md` holds every decision and the
`DESIGN-*.md` documents hold how each area works, and `make unclaimed` fails
when a requirement no document names.

**Two steps of the gate pass only on a commit.** `openapi-current` and
`web-api` diff a regenerated file against the last commit, so on an
uncommitted tree they report the file as stale. Regenerate, commit the
generated file with the change that produced it, and they pass.

## Building

Everything CI runs is a `make` target, so a failure reproduces locally with the
same command and the same pinned versions.

| | |
|---|---|
| `make gate` | The checks this change has to pass, chosen from what it touches. `make gate full` for all of them |
| `make test` | The quick loop: SQLite only, packages in parallel, cached. Seconds |
| `make test-all` | Every configured engine, nothing cached. What `check` runs. The race detector runs on SQLite alone, in a run of its own, because a Go data race does not vary by engine |
| `make check` | Everything CI checks, except the container and chart |
| `make measure` | Measurements rather than gates: what a year of nightly scans does to the tables and the queries. Minutes, and behind a build tag so `check` never runs it |
| `make check-engines` | That all four engines ran, and that each was the engine it claimed |
| `make check-packaging` | The container image and the Helm chart. Needs docker and helm |
| `make build` | The binary, with version information injected |
| `make openapi` | Regenerates the API document from the code |
| `make engines-up` | Starts the four database servers those two checks need |
| `make engines-down` | Removes them |
| `make engines-status` | What is running, and which engines are unconfigured |

**While working, run `make test`.** It is the SQLite-only, parallel, cached
run — a few seconds — and it is what to run after every change. It does not
prove portability, and it says so: every server engine is reported as skipped
by `OPENPSIRT_TEST_ENGINES`, which is a different message from an engine that
is not configured.

**Before committing, run `make gate`.** It reads what the working tree has
changed and runs the tier that change lands in, which is the whole gate for
most commits and seconds for a prose edit. Not `make lint` and `make test`:
those two pass on work that CI rejects, because the gate also runs
`unreachable`, the OpenAPI drift check and the frontend, and because the quick
loop drops the race detector and the three server engines.

**At the end of a session, and before a push carrying accumulated work, run
`make gate full`** — which is `make check && make check-engines`. A clean tree
gets the same answer from `make gate`, because there is nothing there to choose
from.

### The tier is chosen by what the change touches

`DESIGN-build.md` holds the table; the point of the target is that nobody has
to consult it. Two things about it are worth knowing here.

**A change to documents alone is checked as documents**: the document tests and
`make unclaimed`, seconds rather than minutes. That covers both things a
document can actually break — a link pointing at a heading that has been
renamed, and a decision in force that no design document names. Nothing else in
the gate can fail for a prose edit. `check-engines` proves four database
engines ran, which a document cannot affect — it can only pass, and a check
that can only pass is not evidence. Running it anyway is not caution; it is a
habit that makes the gate look expensive and teaches people to skip it.

**The generated files are not documents in this sense.**
`docs/reference/openapi.yaml` and the TypeScript client take the API tier, and
their two steps only pass on a commit anyway. A design document updated
alongside the behavior it describes is in a commit with code in it, which is
the ordinary case and takes the code's tier rather than the document one.

Packages run in parallel in both. Each test binary builds the schema once — a
migrated SQLite file copied per test, and on each server a database of the
binary's own, named for the package, dropped and recreated on first use — so
no package can tear down another's tables (see `internal/dbtest`). The one
thing that still collides is running the *same* package twice at once against
the same server, or the same package from two checkouts hashing alike — the
checkout's directory is in the hash, so that takes a hash collision rather
than a second worktree.

### Why the second command exists

Tests run against SQLite alone unless pointed at real servers, and **a skipped
engine passes**. So a green suite does not mean four engines agreed; it means
nothing failed, which is also what running almost nothing looks like.
`check-engines` greps for each engine by name, refuses when any engine is
unconfigured rather than passing, and — because a grep for a *label* only
proves a subtest with that label ran — asks each server what it is and compares
that against the label. Four URLs differing by a port digit is the likeliest
slip there is, and it used to report fully green.

`make check` names the engines it did not test, rather than staying silent
unless all three are missing.

**What it does not cover.** It asserts three test functions in three packages.
The rest of the suite runs against whatever is configured, so `check-engines`
passing does not prove that every test ran on every engine — it proves the
configuration is real and the migrations, the lock and the identity checks
exercised all four.

This is not hypothetical: a table added with a foreign key to `person` was
missing from the test cleanup, and SQLite alone never noticed. It failed 40
tests on the other three the first time they were run.

### Getting the four engines

 make engines-up

Starts the four servers as containers at the versions CI runs, waits until each
one answers, and writes their URLs to `local.mk` — git-ignored, included by the
makefile if present, so a machine is configured once instead of once per
command. `make engines-down` removes them; `make engines-status` says what is
running and which engines are unconfigured.

**Do not set this up by hand, and do not write `local.mk` yourself.** A setup
document followed by hand is how three engines of four end up unconfigured
while the suite reports green, which is the failure this whole area exists to
prevent. If something about the arrangement needs to change, change the target
so the next machine gets it too.

What it writes, for reference:

 OPENPSIRT_TEST_POSTGRES_URL ?= postgres://postgres:test@127.0.0.1:5432/openpsirt?sslmode=disable
 OPENPSIRT_TEST_MYSQL_URL ?= mysql://root:test@127.0.0.1:3306/openpsirt
 OPENPSIRT_TEST_MARIADB_URL ?= mariadb://root:test@127.0.0.1:3307/openpsirt
 OPENPSIRT_TEST_TOO_OLD_URL ?= postgres://postgres:test@127.0.0.1:5433/openpsirt?sslmode=disable

`?=` rather than `:=`, so setting one in the environment for a single run still
wins. A makefile assignment beats an environment variable; the conditional form
does not.

The last one is a server *below* the supported floor, so the refusal to run
against it is exercised instead of skipped. CI runs a postgres:13 for it.

An existing `local.mk` is never overwritten — it may point at servers of
somebody's own — and the URLs are read when make starts, so the run that writes
the file is not the run that uses it. Run `make engines-up` first, then
`make check && make check-engines`.

### Adding a table

Add it to `tables` in `internal/dbtest`, ahead of everything it points at.
Nothing enforces this and SQLite will not catch it.
