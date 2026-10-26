# Agent instructions for OpenPSIRT

OpenPSIRT takes in the inventory a build produced, scans it for known
vulnerabilities, tracks what changes release to release, and gives people
somewhere to triage findings through to a fix. It is Apache 2.0, installed and
run by other people (REQ-01 and REQ-10).

Read `REQUIREMENTS.md` before proposing anything; most questions are answered
there. If a decision looks wrong, say so and cite its ID. Never quietly
implement something else.

## Document map

| File | Holds | Lifetime |
|---|---|---|
| `REQUIREMENTS.md` | Why: every decision, with reasoning, by area | Permanent |
| `DESIGN-*.md` | How: structures, flows, behavior | Permanent |
| `TODO.md` | What is left: not built, deferred, or waiting on a decision | Until it is empty |
| Code | What runs | — |

### The chain that makes audits possible

Code satisfies a design document, which names the decision IDs it implements,
and a decision says why.

- Code no design document describes is a remnant. Re-examine both; assume neither is correct.
- Keeping the design documents current is part of the change.
- The other direction is checked by the gate: `make check` fails on a decision in force that no design document names, built or not.
- A decision not built yet is named in its area's document, which says in words that it is not built.
- Naming a decision means describing it. An identifier on a `Satisfies` line with no description is an audit trail that lies.
- The gate matches identifiers, not prose: a mention anywhere satisfies it, and `REQ-23, REQ-24, REQ-25` names all three. Whether each is described is a person's judgment.

## Design documents

At the repository root, named `DESIGN-<area>.md`.

- Language-agnostic: behavior, architecture and domain concepts such as SBOM structure, dependency paths, triage outcomes and visibility rules. Never type names, struct fields, function signatures or source paths; those belong in code.
- Name the decisions satisfied, by ID, and describe each.
- A decision that only picks a tool (language, router, query builder, chart library) is not named here. It lives in `REQUIREMENTS.md` alone, and the gate carries the list. A decision joins that list only if it picks a tool and nothing else; listing a behavior decision to quiet the gate defeats the list.
- Record what the decisions did not cover, because an auditor cannot tell an unrecorded choice from an accident.
- Update them in the same change as the code. A lagging design document is trusted and wrong.

### The Spec register

**Spec** is the one register for everything written here: it states what is. It
does not explain, argue, or recount what used to be.

| Surface | Register |
|---|---|
| `DESIGN-*.md` | Spec, with the `Contents` and `Limits` rules |
| `docs/`, `README.md`, `SECURITY.md` | Spec, with no `Limits` block. A `docs/` page has no `Contents`, because the site generates one; `README.md` has one |
| Code comments | Spec, without the `Contents` and `Limits` rules |
| The published API document | Spec, with § The published API document |
| `REQUIREMENTS.md` rows | Spec, plus one clause of reason |
| This file | Spec, and the one place a register's history belongs |
| `TODO.md` | Spec; § The work list says what may reference it |
| Interface strings | Labels, skimmed: `DESIGN-interface.md` § Screen copy |
| Commit messages, pull request descriptions | Why, including what the behavior was and what the change makes of it |

Prior behavior belongs only in the last row. The exception is an upgrade note,
which states what was accepted and what is refused now, because the difference
is what an operator acts on.

Spec has drifted three times, each the same way: question headings, argument
where a statement belongs, and a defect's history in the file describing the
behavior.

| Rule | Detail |
|---|---|
| A heading names a thing | A noun phrase of six words at most. No question, wh-word, or gerund taking an object: "Index responses", not "What an index says". A bare gerund such as "Parsing" is fine |
| A sentence states a fact | Present tense, indicative |
| No antithesis as a frame | Write the true thing; in "X, not Y" the false one is remembered |
| No lead-in sentences | Open on the fact |
| Reason is one clause, or absent | It sits beside its rule; a reason needing a paragraph is a rule not yet found |
| A table cell is a statement | Prose in a column is still prose; history in a cell belongs in a commit message |
| Bold marks a defined term | Never a pressed claim |
| Enumerations are tables | Outcomes, refusals, closure reasons, engine differences, settings, states. `\| rule \| why \|` is the default section shape |
| A table, a list or an example before a paragraph | Parts are a table, steps or cases a list, a shape an example. A paragraph is for the one thing that is none of those |
| Plain words, short sentences | One clause per point; a sentence read twice fails |
| One fact in one place | Point at the owner; two copies disagree |
| Cross-rule rationale goes in `Limits` | The block at the foot of every `DESIGN-*.md`. A published page carries none |
| Every `DESIGN-*.md` opens with `Contents` | One entry per `##` heading, in order |
| Measured numbers stay | "5,047 fixable rows are 271 distinct bumps". Cut the sentence introducing it, never the number |
| Component selection is design | Why this scanner, database or format belongs. Why a variable has its name does not |

A defect that produced a rule is kept as its constraint, in the present tense:
"Candidates are built from the list of ecosystems with an index, never from its
complement", not the story of every ecosystem that passed the filter.

A drifted section has a question for a heading, paragraphs opening on a bolded
claim, a reason sentences past its rule, or a past tense. Rewrite it; do not
append to it.

Checked, because they regress silently: heading form over every markdown file,
the heading bound, and `Contents` lists (`internal/docs/style_test.go`); no bold
in the published API document (`internal/httpapi/reference_test.go`). The rest is
judgment.

#### The published API document

`docs/reference/openapi.yaml` is generated from Go: an operation's `Summary` and
`Description`, and a field's `doc:` tag. Edit it there; an edit to the YAML
survives nothing. It is the one Spec surface published outside this deployment,
read by somebody making a request work.

- A summary is an imperative verb and the thing it acts on, in the domain's words: "Upload an SBOM", "Approve a triage decision". Never a paraphrase such as "Send what a build shipped", "What is open against a build" or "Agree to a claim", because a reader scanning thirty operations has to find theirs in a second.
- A description says what the operation does, takes and returns, and what a caller must know that is not obvious: a 202 that returns before parsing, a field required for one outcome, an approval a later edit withdraws.
- A field's description names the value: "The name a placement is explained by", not "What to call it". A boolean may be "Whether the deployment holds it".
- No case for the design and no decision identifier. The design document owns the argument and is not published.
- A refusal says which request is turned away and what to send instead.
- No bold.

A test fails a missing summary or description, a summary shaped like those
counter-examples or written as a sentence, an operation silent on what it
requires, and a decision identifier. Whether a paragraph explains the design is
a person's call.

## The work list

`TODO.md` is deprecated: new work is a GitHub issue, and nothing is added to the
file. It still holds work in scope, not built and not filed: what must happen
before 1.0, what the owner deferred, decisions not implemented, open questions,
and what was measured and left alone. An item filed as an issue leaves it.

- Every item has an identifier, `TODO-` and a number, never changed or reused, for conversation and pull requests to cite.
- An item says in plain words what exists, what is missing or wrong, the work as an instruction, and what it waits on.
- Code, comments, commit messages and design documents never cite the file or its identifiers; an identifier dies with its item.
- Anything durable moves to `REQUIREMENTS.md` or a `DESIGN-*.md` before an item is deleted.

## Non-negotiables

The decisions easiest to violate by accident and costliest to unpick.

| Rule | Decision |
|---|---|
| No engine-specific SQL in the core. Four engines are supported; engine-specific code lives in the database package and the job queue's locking only, listed in `DESIGN-database.md` and nowhere else | REQ-71 |
| Never trust identifiers a scan file supplies to be stable between builds or consistent between producers. Identity is derived from content | REQ-08 |
| Visibility is enforced in the data-access layer, never per handler, and every query carries a subject: counts, aggregates, search and exports as well as rows | REQ-42 and REQ-43 |
| A finding is a component at a specific place. Never deduplicate up to the package; grouping is presentation | REQ-17 |
| Identity is structural; expiry is version-based. Mixed, an unrelated top-level bump invalidates a leaf decision. The one other expiry is risk lapsing when its issue is rated worse, which concerns the issue, never identity | REQ-25 |
| A test pinning what a query does runs on every engine; SQLite catches no portability trap. A test pinning routing, role reach or a response's shape runs on SQLite and PostgreSQL. The test's SQL decides which | REQ-71 |
| Every transaction is retryable as a whole, through the one helper. A cluster certifies at `COMMIT`, so a write whose statements all succeeded can still roll back | REQ-71 |
| Nothing a transaction depends on is read outside it. A retry re-runs the closure against a moved database | REQ-71 |
| SQL values are parameterized; SQL identifiers come from an allowlist. A placeholder cannot bind a column, so a sort column from a query parameter is the real risk | REQ-66 |
| Every identifier is quoted: declared, named and invented. Engines reserve different words, and a word is reserved only bare. `make reserved` reports bare names; it cannot see a string constant holding one qualified name or a column built from an alias at run time, which are quoted where written. See `DESIGN-database.md` § Identifier quoting | REQ-71 |
| A name a query invents also avoids reserved words. A derived table `groups` fails on MySQL 8; quoting makes it legal, not readable | REQ-71 |
| An affected-row count means rows matched, not changed, so a write whose values were already correct still reports its row. The connection settings make that true on all four engines | REQ-71 |
| Exported code with no caller is a defect. The check counts a test as a caller, so a symbol only its tests reach is a person's to catch | — |
| A decision no design document names is a defect. The gate counts a mention, so naming means describing is a person's to enforce | — |
| The gate never checks that a document is true. Read the code against it; where something is half built, say which half | — |
| A test for a control is verified by breaking the control: watch it fail for the reason it names, then restore it. A control whose test has never been seen to fail is a control nobody has tested | — |
| A request is authorized before any name in it is resolved, or a held and an unheld name are refused differently and a lookup becomes a directory | REQ-42 |
| Every setting offered is one something reads. Zero or negative reads as unset everywhere, so it is refused, not stored | — |
| A name people type matches regardless of capitals; an identity a provider hands over matches exactly. Normalize the stored value, because engines compare loosely in different ways | REQ-08 |

## Measurement before optimization

- Work out an answer when asked. No cache, precomputed total, refresh job or denormalized copy until a measured real deployment shows a real problem. A stale answer brings invalidation, drift and a wrong number nothing reports; copying a hosted product's hourly snapshots adopts its constraints.
- A fact about a moment that cannot be worked out later is stored, for correctness: what a place held before a version moved, how many builds an approval reached.
- A value stored for speed has to earn its place, and is rewritten when its inputs move. A finding's urgency earns it: stored so a list sorts without joining four signals per row, and rewritten when they move (REQ-32).
- Stored never means frozen.

## Two eroding limits

- A short-bump flag is inequality, never ordering. Ordering is per-ecosystem work (Debian epochs, RPM releases, semantic versions, and the rest), and a confident wrong order is a recommendation somebody acts on. No decision records this, REQ-21 does not cover it, and it is the owner's to revisit.
- Every bulk judgment has a cap, and the cap is a setting (REQ-27). Nothing re-checks a dismissal, and an unbounded write is a denial of service somebody triggers by accident.
- A bulk promise to upgrade takes no cap: the next scan re-checks every row it names, and narrowing it makes the record false. `DESIGN-triage.md` holds the transaction-size measurement.
- A cap bounds what is written, never what was asked for, because one named issue expands into many places (REQ-27).

## Source file size

- Target about 1200 lines per source file, as a point to split at; a longer file usually does more than one thing.
- Split by responsibility, never to hit a number. A 1300-line file doing one thing stays whole.
- Act on the trend, because splitting late costs far more.
- Documentation is exempt: a design document splits when it covers two subjects.

## Decisions against facts

`REQUIREMENTS.md` records choices somebody could have made differently. What a
format, engine, ecosystem or protocol requires is a fact, and goes in a design
document: "identity is derived from content" is a decision, and which columns
the hash covers is detail. Assume it is not a decision.

- A row is one plain sentence, with no contractions and no variable, key path, function or version of another specification.
- Adding or removing a row is the owner's call. Ask, quote the wording, wait for a yes, then write it. A yes to the work is not a yes to the row.
- A row may land in the same commit and pull request as its implementation, and usually should.
- `REQUIREMENTS.md` is never edited to record what was built, add a row new behavior seems to want, or reword one. Every change is asked for in those words.

## Decision identifiers

- Rows are sorted by identifier within each table. Append, sort, and cross-reference a related decision; inserting beside it makes entries look missing.
- Identifiers never change, because commit messages and documents cite them.

## Compatibility below 1.0

Below 1.0 there is no schema or API compatibility (REQ-76); the API path version
is a shape, not a promise.

- A schema change edits the declaration within the untagged release's own migration, and a development database is recreated.
- What a tagged release shipped never changes; each release's declarations sit beside its upgrade migration (`DESIGN-database.md` § Migrations).
- Migration 41 is the baseline, v0.7.0's schema at once. An older database is refused.
- Migrations 42, 43 and 44 upgrade databases v0.7.0, v0.8.0 and v0.9.0 built.
- The next schema change is migration 45, edited until a tag ships it.
- At 1.0 the baseline becomes 1.0's schema, beside one migration from the last 0.x release, which `TODO.md` records.

## Evidence beside a decision

A decision settled by a measurement carries it: "335,021 findings for one image,
305,487 of them a single kernel across 62 modules"; "3 ms on PostgreSQL, 11 ms on
MySQL, for the worst component in a real graph". A number can be re-checked in
two years and records why the decision was taken then. A reversal records what
was believed, what was measured, and which was wrong.

## Code conventions

- No timeline language: "for now", "temporarily", "first cut", "later", "in this phase", "step N". Describe a missing behavior as a limitation.
- A comment describes the code that is there: would it still be true had the code always looked like this? Keep the constraint that forces the shape ("a float compares differently, and this has to sort in an index") and its measurement. The story of the edit goes in the commit message.
- Comments narrating history are fixed as their files are touched, not in a sweep.
- No count of the tree's own contents in comments, documents or descriptions, such as "fifteen class names are styled by nothing"; it is false as soon as anybody edits what it counts. Say the shape; a gate prints the count.
- A measurement of something outside the repository stays, such as "1,415 against 38".
- No ticket or tracker references in code, comments or documents. Keep linkage in the tracker and the pull request.
- Comment density matches the surrounding code. Explain why, not what.
- Interface copy is labels: cut first, then say what a thing is or does in a couple of words, with clarification on hover, in plain spoken English for a technical reader. Contractions are allowed there. `DESIGN-interface.md` § Screen copy holds the rest.
- American spelling in prose, comments and identifiers: license, catalog, normalize, behavior, color, authorize. Text quoted from a producer and field names a consumed format defines are exempt.
- No contractions in anything durable; temporary documents and commit messages are exempt.
- Write OpenPSIRT wherever a person reads it: documentation, the API description, the version the binary prints, a chart description.
- Lower case for what is typed or matched: `openpsirt migrate up`, the module path, the container image, the chart, the `OPENPSIRT_` prefix, `cmd/openpsirt/`.

## Security review checklist

Worked through on every review (REQ-75), for this codebase.

| Category | Check |
|---|---|
| Injection: SQL | Values parameterized; identifiers from an allowlist, since a sort column or filter field cannot be bound (REQ-66). Nothing is partitioned, so no partition names to guard |
| Injection: output | SBOM names, versions and descriptions come from a third party and reach the staff with the most access: encoded on output, never through the markdown renderer (REQ-66). A URL from a scan or feed has its scheme allowlisted before it becomes a link, and is shown unlinked where it fails |
| Injection: markdown | At submission, before storage: raw HTML refused naming its line (never escaped; a parser option reaches nothing); only `http`, `https` and `mailto` links, and `//` or `/\` is another host; nothing remote fetched, images included. Source stored, never HTML. Nothing on the server renders, so the renderer sanitizes: the interface, or an integrator's own application. The renderer allowlists the fenced-block language tag before it reaches a class attribute (REQ-67) |
| Broken access control | Data layer with a subject, including counts, aggregates, search and exports (REQ-42 and REQ-43). An attachment fetch is authorized against its finding's visibility before any signed URL is issued (REQ-70) |
| Cryptographic failures | API keys and personal tokens hashed at rest and shown once (REQ-68). Session identifiers unguessable |
| Insecure design | Does the change contradict a recorded decision? Cite it |
| Security misconfiguration | Container non-root, read-only root filesystem. Trusted-header sign-in off by default and only from configured sources (REQ-41) |
| Vulnerable components | `govulncheck` and dependency review gate. A new dependency needs a permissive license (REQ-01) |
| Authentication failures | No account for anybody nothing authorized in advance. In group-bound mode the mapping is that authorization: a record is written on first arrival for somebody it covers; every other path refuses an unknown arrival. Unauthorized users get a generic message that does not say why (REQ-41) |
| Data integrity | A scan file is hostile: bounded size, depth and component count, never a filesystem path (REQ-66 and REQ-69). Markdown fields are length-bounded and never rendered on the server (REQ-69) |
| Separation of duties | An approval points at one revision of a justification. Anything letting approved text change without withdrawing the approval defeats REQ-24 (REQ-28) |
| Logging failures | Secrets never logged. Triage actions land in the append-only history (REQ-68) |
| Request forgery | Where a document chooses the host (a patch link's repository through the loopback proxy, REQ-78; a supplier's directory and documents), the request reaches nothing inside this network or on the administrator's excluded list, checked at connect time on the resolved address, and follows no redirect; the excluded list alone keeps out an internal service on a public name. Every other outbound request goes only to a configured or application-named host: sign-in and package indexes pinned; webhooks, mail and the object store where configured, private addresses included (REQ-69) |

## Testing

- Every change runs against all four database engines in CI.
- Fixtures include a real SBOM per supported producer, and one full-size fixture for performance work.
- Authorization is tested as a matrix of role × visibility × endpoint, including counts, aggregates, search and exports.
- Regression tests are named for the invariant they pin, never for an item on a list.
- A gate iterating a collection counts what it examined and fails on zero, and a gate joining two sets reports both directions. `internal/config/documented_test.go` is the form: `if len(reads) == 0 { t.Fatal("no settings were found in the source, so this checked nothing") }`, reporting a setting documented and not read, and one read and not documented.
- A gate never rests on a hand-written list of what to check, or an exit code with its message discarded. A gate reached only by running the program over the tree has its detection lifted into a function, with one input it must report and one it must not.
- A test named for an arm has an input reaching only that arm. Check coverage of the named line with `go test -coverprofile`; a passing test proves nothing when its corpus misses the arm.
- Two tests are redundant only when they take the same path through the code. In `sharedVersion` (`web/src/ui/versions.ts`), "says nothing where the versions differ" reaches the comparison and "leaves a level of one alone" returns at the length test, so both stay. A level of none takes the second's path and has no test of its own. Cite tests by name, never by line.

## Commits and pull requests

- No `Co-Authored-By` trailers; tell tooling that adds one not to. Under DCO only `Signed-off-by` carries meaning, and a co-author trailer claims authorship nobody signed for. This holds from the root commit; the imported history, where tooling added one to 79 of the last 400 commits, was not brought across.
- Nothing about how a change was produced: no tool, assistant, session or generated-by footer in a description, title, commit, branch name, code or review comment. The sign-off says a person wrote it and stands behind it.
- The body explains why; the diff shows what.
- Design document updates go in the same commit as the behavior they describe.
- Every change reaches `main` through a pull request and the merge queue, administrators included.
- `Merge Status` is the one required check. It waits for every other check to pass or be skipped, so every workflow meant to gate a merge declares `merge_group:` beside `pull_request:`; a workflow with no check run on an event looks like one not yet started.

### Pull request descriptions

Read by somebody deciding whether to review now, and later by somebody working
out why the code looks as it does.

- The title is an imperative verb, then the feature, screen or defect by its searchable name, in one clause of about 50 characters with no "and": "Speed up the Inventories page", "Make v0.7.0 the oldest supported schema". Never a paraphrase naming nothing, such as "Report failures as what they are". Squash-merge makes it the subject on `main` and a release-notes line.
- Short, plain spoken English, as `DESIGN-interface.md` § Screen copy describes.
- Lists, tables and before-and-after examples before prose.
- A measurement where there is one.
- No count of the tree's own contents: "every trailed act", not "38 trailed acts", because the description changes as the branch does.
- A screenshot where the layout moved, attached with `--attach './shot.png#alt text'` on `gh pr create`, `gh pr edit` or `gh pr comment`. Never hosted on a branch, whose deletion breaks the links, and never a `data:` image, which GitHub strips.
- What is left undone is said.

### Development workflow

- Commit and push as work lands, in purposeful pieces, each with a why-body. A working tree is one accident from gone.
- `main` is never pushed to directly and its history never rewritten. A pull request branch belongs to its author, who rebases it onto `main` and force-pushes with `--force-with-lease`.
- Run `make gate` before every commit and `make gate full` before a push carrying more than one, rather than waiting for CI to fill the queue with entries that will not merge.
- `openapi-current`, `web-api` and `reserved-current` diff a regenerated file against the last commit, so they pass only once the file is committed with its change.
- The history starts at the import: `main` has one root commit and every later commit came through a pull request. The reasoning lives in `REQUIREMENTS.md` and the design documents.

## Building

Every CI step is a `make` target, so a failure reproduces locally with the same
pinned versions. `DESIGN-build.md` § Make targets lists them all.

| Target | Use |
|---|---|
| `make test` | After every change. SQLite only, parallel, cached, seconds. Server engines are reported skipped by `OPENPSIRT_TEST_ENGINES`, which differs from unconfigured |
| `make gate` | Before committing: the tier the working tree's changes land in |
| `make gate full` | At the end of a session and before a push carrying accumulated work: `make check && make check-engines`. A clean tree gets it from `make gate` |
| `make test-all` | Every configured engine, uncached; what `check` runs. The race detector runs on SQLite alone, since a data race does not vary by engine |
| `make check` | Everything CI checks except the container and chart. Names any engine it did not test |
| `make check-engines` | That all four engines ran, each was the engine it claimed, and the reserved-word list matches them |
| `make measure` | What a year of nightly scans does to tables and queries. Minutes, behind a build tag `check` never sets |
| `make check-packaging` | The container image and Helm chart; needs docker and helm |
| `make build`, `make openapi` | The binary with version information; the API document from the code |
| `make engines-up`, `-down`, `-status`, `-clean` | Start, remove and report the four servers; drop test databases no running test holds, safely during other runs |

`make lint` and `make test` alone pass work CI rejects: they skip `unreachable`,
the OpenAPI drift check, the frontend, the race detector and three engines.

### Tier selection

`DESIGN-build.md` § Gate tiers holds the table, and `make gate` applies it.

- A change to documents alone runs the document checks only, in seconds.
- `check-engines` never runs for a documents-only change: it can only pass, and running it teaches people the gate is expensive.
- The generated `docs/reference/openapi.yaml` and TypeScript client take the API tier.
- A design document committed with code takes the code's tier.
- Test binaries run in parallel, each with its own database per server through a leased slot (`DESIGN-build.md` § Test databases).

### The second command

A skipped engine passes, so a green suite proves only that nothing failed.
`check-engines` refuses when any engine is unconfigured, and asks each server
what it is, because four URLs differing by a port digit pass a grep for labels.
It proves the configuration is real and that the migrations, lock, identity
checks and word list ran on all four, and that a half-applied migration was
re-run on the two engines that leave one. It does not prove every test ran on
every engine. A table missing from test cleanup once passed on SQLite and failed
40 tests on the other three.

### The four engines

- Configure them with `make engines-up`, which starts containers at CI's versions and writes their URLs to the git-ignored `local.mk`. Never set them up by hand or write `local.mk` yourself; change the target instead. A hand setup is how three engines go unconfigured while the suite reports green.
- An existing `local.mk` is never overwritten; it may point at somebody's own servers.
- Make reads the URLs when it starts, so run `make engines-up` first, then `make check && make check-engines`.
- Its settings use `?=`, so an environment variable wins for one run.
- One server is below the supported floor (postgres:13 in CI), so the refusal is exercised.
- `OPENPSIRT_TEST_RELAX_DURABILITY` marks the MySQL and MariaDB servers as throwaway, because their durability setting is global to the server. Left out, a server keeps its own.

### A new table

- Add it to `tables` in `internal/dbtest`, ahead of everything it points at.
- A test holds membership against the migrated schema in both directions: a table missing from the list is never emptied, and an extra name deletes from nothing.
- The order is judgment, read from the foreign keys; a position that needed reasoning carries a comment. An ordering mistake fails only on engines that enforce foreign keys in a bulk delete, so it looks engine-specific.
