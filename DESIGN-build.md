# Build and validation

Repository layout, the gate, and what stops a change reaching `main`.

Satisfies REQ-01, REQ-61, REQ-63, REQ-75.

## Contents

- [Layout](#layout)
- [Make targets](#make-targets)
- [Gate tiers](#gate-tiers)
- [CI jobs](#ci-jobs)
- [Interface checks](#interface-checks)
- [Class-name checks](#class-name-checks)
- [Database engines](#database-engines)
- [Test databases](#test-databases)
- [Pinned pairs](#pinned-pairs)
- [Static analysis](#static-analysis)
- [Licenses](#licenses)
- [The API document](#the-api-document)
- [Self-inventory](#self-inventory)
- [Probes](#probes)
- [Documentation](#documentation)
- [The review checklist](#the-review-checklist)
- [Actions are pinned](#actions-are-pinned)
- [Repository settings](#repository-settings)
- [Limits](#limits)

## Layout

| Path | Holds |
|---|---|
| `cmd/openpsirt/` | The binary. Flag parsing, configuration, server lifecycle |
| `internal/version/` | What this build is. Values injected at link time |
| `internal/config/` | Settings, read from the environment with working defaults |
| `internal/httpapi/` | The HTTP surface and the operations the API document is generated from |
| `internal/database/` | Opening, identifying and validating a database. See `DESIGN-database.md` |
| `internal/database/migrate/` | The migration runner and the locks around it |
| `internal/database/migrate/migrations/` | The migrations |
| `internal/schema/` | Applies this application's schema. Exists so that using the runner registers the migrations |
| `internal/dbtest/` | Runs a test against every database available to it |
| `internal/catalog/` | Products, streams and variants. See `DESIGN-data-model.md` |
| `internal/ingest/` | Arriving scans. See `DESIGN-ingest.md` |
| `internal/queue/` | Durable background work. See `DESIGN-queue.md` |
| `internal/sbom/`, `internal/scanner/` | Reading an inventory and scanning it. See `DESIGN-ingest.md` |
| `internal/graph/`, `internal/finding/` | The dependency graph and what a scan found. See `DESIGN-data-model.md`, `DESIGN-findings.md` |
| `internal/triage/`, `internal/advisory/` | Judgments, approvals, and the CSAF document. See `DESIGN-triage.md` |
| `internal/access/`, `internal/signin/` | Subjects and sign-in. See `DESIGN-access.md` |
| `internal/notify/` | Notifications. See `DESIGN-notifications.md` |
| `internal/markdown/`, `internal/setting/`, `internal/currency/` | Text policy, administrator settings, and upstream version lookups |
| `internal/webui/` | The built interface, embedded. See `DESIGN-interface.md` |
| `internal/docs/`, `internal/tools/` | Document checks and the gates that are not linters |
| `web/` | The interface source. See `DESIGN-interface.md` |
| `deploy/helm/openpsirt/` | The chart. See `DESIGN-packaging.md` |
| `docs/` | The published documentation site |
| `assets/` | Logo files |

Everything is under `internal/`, so nothing is importable by another module.

## Make targets

Every check CI runs is a `make` target, so a CI failure reproduces locally with
the same command and the same pinned tool versions (REQ-75).

| Target | Runs |
|---|---|
| `make build` | The binary, with version information injected |
| `make gate` | The checks this change has to pass, chosen from what it touches |
| `make gate full` | All of them, whatever the change touches |
| `make test` | SQLite only, packages in parallel, cached. Seconds |
| `make test-all` | Every configured engine, nothing cached: the two runs below |
| `make test-race` | SQLite with the race detector, tests within a package beside each other |
| `make test-engines` | The three server engines, without the detector |
| `make docs-check` | What a change to documents alone can break |
| `make lint` | Static analysis, pinned version |
| `make vet` | The compiler's own checks |
| `make govulncheck` | Known vulnerabilities in dependencies |
| `make licenses` | Shipped dependency licenses against the allowlist |
| `make openapi` | Regenerates the API document from the code |
| `make openapi-current` | The committed API document against what the code generates |
| `make sbom` | This project's own CycloneDX inventory |
| `make web-check` | Interface: locked install, type check, Prettier, ESLint, Stylelint, tests, class-name checks, and the generated client diffed against the API document |
| `make unreachable` | Exported code nothing reaches |
| `make unclaimed` | Every requirement is named by a design document |
| `make pins-check` | Every version pinned in two files still agrees |
| `make check` | Everything above |
| `make check-engines` | That all four engines ran, and that each was the engine it claimed |
| `make check-packaging` | The container image and the Helm chart. Needs docker and helm |
| `make dist` | Every release asset, into `bin/dist`, each checked against the tag it names. Needs docker and helm. See `DESIGN-packaging.md` |
| `make docs-site` | The documentation site, built strictly. Needs mkdocs |
| `make engines-up` / `-down` / `-status` | The four database servers |
| `make measure` | Measurements rather than gates. Behind a build tag |

## Gate tiers

The full gate is minutes, and most changes cannot fail most of it: a prose edit
cannot break a database engine, and an interface change cannot make a Go query
non-portable. Running everything anyway is what teaches people to skip the gate,
which is the failure the gate exists to prevent (REQ-75).

`make gate` reads what the working tree has changed and runs the tier that
change lands in. The tiers accumulate: a commit carrying a design document and a
query runs both.

| Touched | Adds |
|---|---|
| `*.md` alone | the document tests, and `unclaimed` |
| `web/**` alone | `web-check` |
| Go reaching no SQL | `build`, `vet`, `lint`, `unreachable`, `readable`, `test` |
| a query, the schema, a migration, or the harness the tests share | `reserved`, `test-all`, `check-engines` |
| Go the API document is generated from | `openapi-current`, `web-api` |
| anything else, or nothing | the whole gate |

| Rule | |
|---|---|
| **The choice is a program's, not a person's** | A table is read optimistically at six in the evening; a program reads the same change every time |
| **A path nobody classified takes the whole gate** | The makefile, the container, the chart, an asset, a fixture. Being generous about a handful of paths costs less than a tier that quietly omits one |
| **A Go file is classified by what the whole file holds** | Not by what the edited lines hold. A change anywhere in a file of queries can move what a query returns |
| **A clean tree takes the whole gate** | Nothing there to choose from, and a clean tree before a push is carrying work that is already committed |
| **`test-all` replaces `test`** | The same tests, against four engines rather than one |
| **Local and CI run the identical command** | The moment they differ, "it passed locally" stops meaning anything |

Two steps pass only on a commit — `openapi-current` and `web-api` diff a
regenerated file against the last commit, so on an uncommitted tree they report
the file as stale.

## CI jobs

Four, and each of the three beside the first is separate for a reason of its own
rather than for tidiness.

| Job | Holds | Why it is not a step of the first |
|---|---|---|
| Build, test and check | `engines-check`, `make check`, `check-engines`, and the bill of materials as an artifact | — |
| Dependency review | The license policy applied to what a pull request adds | Pull requests only, needs no toolchain, and is an action rather than a make target |
| Container image and chart | The image built, then `check-packaging` against it | buildx and helm rather than Go, and it carries a build cache of its own |
| Documentation builds | The documentation site built | Python, and nothing else needs it |

Two workflows beside this one report no build of their own. `PR` is the
aggregator that waits for every check here and is the only one the ruleset
names; `Release` runs on a tag and is described in `DESIGN-packaging.md`.
Both declare `merge_group:` as this one does — a workflow that does not
contributes no check to a queue entry, and the aggregator cannot tell that
from one that has not started.

**The first job runs one target, not a list of them.** `make check` is the
definition of what CI checks, so a target added to it is run by CI without
anybody remembering to add a step.

**Naming targets individually is how the two drifted.** CI was six jobs listing
their targets by hand, and three targets `make check` runs were in no job:
`reserved`, `readable` and `pins-check`. So the rule that local and CI run the
identical command was written down, believed, and false in three places —
including the one that checks no invented name collides with a word an engine
reserves, which is a non-negotiable.

**Five of the six were a checkout and a Go setup.** The interface, static
analysis, vulnerabilities and licenses, the API document and the bill of
materials each declared nothing else before running a make target: same runner
image, same toolchain, same module cache, no services, no conditions. Six clones
and six toolchain restores did one machine's worth of work. Parallelism was the
only thing lost by folding them together, and it was not what any of them was
for.

**A composite action was considered and is not needed.** The shared setup was
going to become one, but after the fold there is exactly one Go setup left in
the workflow, so an action abstracting it would have a single caller. A reusable
workflow would not have helped at all: it runs on a runner of its own, so it
re-clones and re-installs, which organizes the file and keeps the cost.

**Publishing documentation is a workflow of its own**, not this one's fourth
job. It runs on `main` alone, writes to the repository, and publishes rather
than checks.

## Interface checks

| Tool | Covers |
|---|---|
| `tsc` | Strict, with unused locals and parameters, unchecked indexed access and verbatim module syntax |
| ESLint | Only what `tsc` has no view of. The rules of hooks are the reason it is present |
| Prettier | Formatting, for TypeScript and CSS. The counterpart to `gofmt` |
| Stylelint | CSS correctness: unknown properties, duplicate selectors, notation. Nothing about whitespace |
| `npm run classes` | Two questions about class names, below |

Formatting belongs to one tool. Stylelint's whitespace rules are off rather than
left to disagree with Prettier.

ESLint is deliberately narrow. A second opinion about style is noise beside a
formatter, and a rule that fires on working code teaches people to read past the
output. What it carries is the hook rules, which catch an impure read during
render, a dependency list that makes an effect run every time, and a value
assigned and never used.

One rule reports rather than refuses: writing state from an effect, flagged nine
times, all the same shape. The fix is to remount with a key, which changes how
those components mount rather than what they do, so each has to be driven in a
browser.

## Class-name checks

**A class name this project defines that Tailwind also defines.** Tailwind is
imported wholesale, so it emits a utility rule for any class name in the source
it recognizes. Where that name is also defined here, both rules apply and
Tailwind's wins for the properties it sets. Nothing fails: a column with
`class="col fixed"` picked up `position: fixed` and left the grid.

The set is derived rather than listed. Every class this stylesheet defines a rule
for is put to Tailwind's compiler, and anything it answers for is a collision. A
utility Tailwind adds in a later version is caught on the next run.

**A rule that styles nothing.** Matched against the whole source rather than
against `className=`, because class names are built as well as written:
`col ${kind}` puts a modifier in the markup that appears nowhere as a literal.
The check is deliberately weak — it finds a name mentioned nowhere at all, and
stays quiet otherwise. Names from a charting library or the markdown renderer's
`language-` prefix are excluded.

## Database engines

The suite runs against SQLite alone unless pointed at real servers, and **a
skipped engine passes**. A green run does not mean four engines agreed; it means
nothing failed, which is also what running almost nothing looks like.

`make engines-up` starts them, waits until each answers, and writes their URLs to
`local.mk` — git-ignored, included by the makefile if present.

| Property | Reason |
|---|---|
| Each server is asked with its own client, inside its own container | A container reported "Up" is not one that answers, and nothing should depend on a client installed on the machine |
| `local.mk` is never overwritten | It is machine-local, and may point at an operator's own servers |
| Starting is idempotent | A running engine is left alone; a stopped container is started rather than replaced |
| Images are pinned and compared against CI's, in both directions, with CI running the check | A local four-engine pass means what CI's means only if they are the same servers |
| One of the four is below the supported version floor | The refusal to run against an old server is exercised rather than skipped |

The URLs are read when make starts, so the run that writes `local.mk` is not the
run that uses it.

## Test databases

Every test binary is one package, and every package holds a database of its own
on each engine, so packages share nothing and run in parallel.

| Engine | What a test gets | Emptied between tests |
|---|---|---|
| SQLite | A copy of a template migrated once per binary | Not needed — each test holds its own file |
| The three servers | The package's own database on the server | By deleting from the tables that hold rows |

**A server database is kept between runs and reused.** Applying the migrations
was nearly the whole cost of a server engine — 11.2 s on MySQL and 6.2 s on
MariaDB, once per package per engine, which was 475 s of server work in a run
that spent 43 s of processor time — and none of it tests anything the migration
tests do not.

What makes reuse safe is the name. Until the first release a schema change edits
the migration that created the thing rather than adding one beside it, so the
applied version does not move and only the content of the migrations tells one
schema from another. The name therefore carries a fingerprint of the migration
sources: an edited migration names a different database rather than reusing a
stale one, and the databases the older fingerprints named are dropped as the new
one is created, so a server does not accumulate them. A kept database is emptied
before the first test sees it.

**The race detector runs on SQLite alone.** A Go data race does not vary by
database engine, and the detector's cost is in-process work — which is most of
what SQLite spends and almost none of what a server engine does.

| `internal/httpapi`, one engine | With the detector | Without |
|---|---|---|
| SQLite | 73.6 s | 10.1 s |
| PostgreSQL | 59.6 s | 33.5 s |
| MySQL | 18.5 s | 12.0 s |
| MariaDB | 16.9 s | 12.0 s |

The detector is a property of the binary and cannot be turned on for one
subtest, so `test-all` is two runs: SQLite with it, the three servers without.

**Tests within a package run beside each other when SQLite is the whole run.**
That is the only run where each test already holds a database nothing else can
reach; on a server the package has one database and its tests empty it between
themselves, so two at once would clear each other's rows. A test that changes
something the whole process shares — an environment variable, the working
directory — says so and runs alone.

Together: four minutes four seconds became one minute fifteen against warm
servers, and two minutes forty-five against cold ones.

## Pinned pairs

A version written in two files is a version somebody moves in one of them: the Go
toolchain the container builds with against the one the module declares, the Node
the image uses against the one CI runs, the SBOM generator in the image against
the one the SBOM target invokes.

A check of its own rather than part of the engine check: that answers what the
tests run against, this answers what the release is built from. It found drift on
its first run — the image carried two defaults for the version passed in, so a
build with none reported `dev` in the binary and `0.0.0` in its own inventory.

## Static analysis

Rule selection lives in `.golangci.yml` and nowhere else. **Two scopes only**: a
rule gates, or it is advisory. There is no third scope for grandfathering a
backlog (REQ-75).

The linter set is tuned rather than enabled wholesale. Documentation rules are
off; error checking excludes the cleanup-path functions conventionally ignored.

The linter must be built with a Go release at least as new as the code, or it
cannot read the compiler's export data and fails on every file with a message
about import versions. The pinned version moves when the language version does.

## Licenses

Permitted for shipped dependencies: Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
MIT, MPL-2.0 (REQ-01).

Checked two ways, because they catch different things: `make licenses` walks what
the module links, and dependency review inspects what a pull request adds.

A short exception list covers modules whose license the classifier cannot read.
Each entry names the license and why the tool fails on it, and the license has
been read by hand before being added. Lowering the classifier's confidence
threshold would accept every other unreadable license silently.

Build tooling is exempt. The linter is GPL-licensed; running a tool over the code
affects its license no more than the compiler does.

## The API document

Generated from the operations registered in `internal/httpapi`, never written by
hand (REQ-61). CI regenerates it and fails if the committed copy differs. What
each operation asks of a caller rides on the same document (REQ-62), so "who may
call this" is checked by the same diff.

The application serves the document itself, authenticated like every other route,
and nothing that renders it (REQ-63).

## Self-inventory

Generated from the built binary's module graph rather than from source, so it
describes what ships (REQ-04). CycloneDX, the format this project treats as
authoritative on the way in.

License fields are not populated reliably by the generator and nothing depends on
them; compliance is gated by the allowlist check. The file is also this project's
first test fixture.

## Probes

`/healthz` and `/readyz` answer without authentication and report nothing beyond
whether the process is up. A container probe cannot sign in. They are outside the
documented API and must never grow a response body describing the system's
contents.

They are not the only routes answering without a credential; the sign-in paths
and the interface's assets do too. **None of them reads anything from the
database about what this deployment holds** (REQ-43).

## Documentation

Built with mkdocs-material and published to GitHub Pages on every push to `main`,
with sets versioned by `mike` (REQ-63).

The configuration page lists every environment variable the process reads, with
its meaning and default. A variable that is set and cannot be read stops the
process with the variable named rather than falling back.

## The review checklist

The checklist in `AGENTS.md` is worked through on every review rather than
consulted when somebody remembers (REQ-75).

It is not enforced by the pipeline. What CI can check, CI checks; the gate is
long precisely so the checklist holds only what a machine cannot decide.

## Actions are pinned

| Rule | Why |
|---|---|
| Every action is pinned to the commit of a release, with the version in a comment beside it | A tag moves. An action that moves is code running with this repository's token on a day nobody chose, and `v4` is a tag |
| The repository requires it | `sha_pinning_required` refuses a workflow referencing an action by tag, so the rule is enforced rather than remembered by whoever writes the next workflow |
| Dependabot moves the pins, weekly, as one pull request | A pin nobody moves is a version that stops receiving fixes with nothing saying so. Grouped, because these move together and separately they are noise nobody reads by the fourth one |
| An update arrives through the queue like anything else | The commit being pinned is visible in the diff, and the gate runs against it |

## Repository settings

Nothing here is in a file, so each is listed with what it is for and what its
absence looks like — an absent setting fails somewhere far from itself.

| Setting | Needed by | Symptom when off |
|---|---|---|
| Every change through a pull request, no direct push to `main` | The gate meaning anything | A commit reaches `main` having passed nothing |
| Merge queue, squash, `ALLGREEN` | Landing what was tested | A pull request green against a `main` that has since moved |
| One required check, `Merge Status` | Every other check | A workflow added later gates nothing until somebody edits the ruleset |
| GitHub Advanced Security | Dependency review, on a private repository | "Dependency review is not supported on this repository" |
| Dependency graph, via Dependabot alerts | Dependency review | The same |
| Secret scanning and push protection | REQ-75 | A credential reaches the history, where deleting it does not remove it |
| Actions pinned to a SHA | The section above | A tag somebody else controls executes here |
| Pages, serving the `gh-pages` branch | Documentation publishing | The workflow succeeds and nothing is served |

**Private and public differ.** Secret scanning and push protection are on by
default for a public repository and are switched on explicitly here; dependency
review needs Advanced Security while the repository is private, and needs
nothing once it is public. A private Pages site is served only to accounts with
read access, at a generated address rather than at the organization's.

## Limits

- **Branch protection is not enforced.** The gate runs on every pull request but
  nothing blocks a merge, which is the state REQ-75 warns about. Deliberate for
  early development, and it needs revisiting before outside contributions.
- **The documentation workflow publishes one set, `main`, as the default.**
  Publishing a tag under its version and moving a `latest` alias belongs with a
  release process that does not exist. The versioning machinery is in place.
- **The install and operate guides are not written.** Both are about a release —
  how to get a version, how to move between them, what to back up before an
  upgrade — and there is no release process, so a guide written now would describe
  the demo target and the development database.
- **The gate and CI run the same commands.** The packaging checks existed twice,
  neither a superset of the other, so a reviewer running the gate and a merge being
  blocked were checking different things.
- **A check needing a running server refuses rather than skips.** A skipped test
  passes, and "the suite is green" and "the suite ran" are two different facts
  behind one command.
- **`README.md` and `docs/index.md` are compared.** Neither can include the other,
  and they drifted in five of ten lines.
