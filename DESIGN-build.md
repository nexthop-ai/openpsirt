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
- [Commit durability](#commit-durability)
- [Pinned pairs](#pinned-pairs)
- [Hash pinning per ecosystem](#hash-pinning-per-ecosystem)
- [Static analysis](#static-analysis)
- [Gate inputs](#gate-inputs)
- [Licenses](#licenses)
- [The API document](#the-api-document)
- [Self-inventory](#self-inventory)
- [Probes](#probes)
- [Documentation](#documentation)
- [The review checklist](#the-review-checklist)
- [Action pinning](#action-pinning)
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
| `internal/rating/` | How a product's own rating of an issue is spelled in a query, where both sides of the graph may say it. See `DESIGN-findings.md` |
| `internal/triage/`, `internal/advisory/` | Judgments, approvals, and the CSAF document. See `DESIGN-triage.md` |
| `internal/access/`, `internal/signin/` | Subjects and sign-in. See `DESIGN-access.md` |
| `internal/notify/` | Notifications. See `DESIGN-notifications.md` |
| `internal/obligation/` | The windows a deployment counts after an attack, the notices given, and the shelf over both. See `DESIGN-obligations.md` |
| `internal/markdown/`, `internal/setting/`, `internal/currency/` | Text policy, administrator settings, and upstream version lookups |
| `internal/attach/` | Files that hang off an issue, and what may be served back. See `DESIGN-attachments.md` |
| `internal/trail/` | What somebody changed about how this deployment works. See `DESIGN-access.md` |
| `internal/saved/` | A narrowing of a list somebody kept, and the claim it prepares. See `DESIGN-remediation.md` |
| `internal/vex/`, `internal/publisher/` | What we have decided about what a build ships, and who says so. See `DESIGN-remediation.md` |
| `internal/directory/` | The advisories that have gone out, written where somebody else's web server serves them. See `DESIGN-remediation.md` |
| `internal/supplier/` | The publishers whose advisories are read on a schedule, and what a pass over one takes. See `DESIGN-ingest.md` |
| `internal/patchbranch/` | Which branches hold the commits patch links name, the repository copies that answer it, and the proxy git reaches out through. See `DESIGN-findings.md` |
| `internal/vercmp/` | Ordering two versions of one package, where the ecosystem defines one. See `DESIGN-remediation.md` |
| `internal/outward/` | The one HTTP client this process reaches the internet with. See `DESIGN-access.md` |
| `internal/background/`, `internal/bound/` | A pass on a timer, and cutting a string to a number of bytes without splitting a character |
| `internal/webui/` | The built interface, embedded. See `DESIGN-interface.md` |
| `internal/weakness/` | What the weakness catalog calls each identifier, read from what it publishes. See `DESIGN-remediation.md` |
| `internal/docs/`, `internal/build/`, `internal/tools/` | Document checks, makefile checks, and the gates that are not linters |
| `web/` | The interface source. See `DESIGN-interface.md` |
| `deploy/helm/openpsirt/` | The chart. See `DESIGN-packaging.md` |
| `docs/` | The published documentation site |
| `assets/` | Logo files |
| `Makefile` | The build, every gate, and what they clean up |
| `Makefile.demo` | The image and what is built from it: the seeded demo deployment, the hot-reload loop, and the offline scanner bundle. Included by the makefile beside it, so every target is reached the same way. A file of its own because it shares nothing with the gate half but the names of the docker and npm commands, so the half that decides whether a change may be pushed reads without the half that stands an instance up. The scanner bundle is here because it is built from the demo image rather than because it is a demo target, and every variable these read is here with them |

Everything is under `internal/`, so nothing is importable by another module.

Two import constraints are worth stating, because a fix proposed without them
cannot be written:

| Constraint | Why |
|---|---|
| `internal/database` cannot read a setting | `internal/setting` imports `internal/database`, so a bound read from the settings store cannot live below it. Bounds that low come from the environment |
| The schema's tests cannot reach the harness's table list | They are an external test package, and the list is the harness's own |

## Make targets

Every check CI runs is a `make` target, so a CI failure reproduces locally with
the same command and the same pinned tool versions (REQ-75).

The Go package pattern is not `./...`. An npm dependency ships a Go package —
`web/node_modules/flatted/golang` — and `./...` matches it, so it is compiled,
vetted, tested and scanned as part of this module. Nobody chooses that: a
JavaScript dependency putting Go source into the build graph is a surface
rather than a curiosity. Every tool written here skips `node_modules` by name,
and the package pattern is the list `go list` gives minus that directory,
computed rather than written out so a new directory of ours needs no edit.

| Target | Runs |
|---|---|
| `make build` | The binary, with version information injected |
| `make gate` | The checks this change has to pass, chosen from what it touches |
| `make gate full` | All of them, whatever the change touches |
| `make test` | SQLite only, packages in parallel, cached. Seconds |
| `make test-all` | Every configured engine, nothing cached: the two runs below, at once |
| `make test-race` | SQLite with the race detector, tests within a package beside each other |
| `make test-engines` | The three server engines, without the detector |
| `make docs-check` | What a change to documents alone can break |
| `make lint` | Static analysis, pinned version |
| `make vet` | The compiler's own checks |
| `make govulncheck` | Known vulnerabilities in dependencies |
| `make licenses` | Shipped dependency licenses against the allowlist, Go and npm |
| `make web-audit` | Known vulnerabilities in what the interface installs |
| `make secrets` | Credentials in what a commit could carry — tracked files as they stand and untracked files git does not ignore — with a pinned scanner |
| `make openapi` | Regenerates the API document from the code |
| `make openapi-current` | The committed API document against what the code generates |
| `make sbom` | This project's own CycloneDX inventory |
| `make web-check` | Interface: locked install, type check, Prettier, ESLint, Stylelint, tests with coverage, class-name checks, and the generated client diffed against the API document. Refuses without npm rather than skipping |
| `make unreachable` | Exported code nothing reaches |
| `make negatives` | A 404 built from an error's own text: it asserts a name reaches nothing, and publishes whatever the error carried |
| `make granted` | Every query outside the access package asks both grant tables |
| `make narrowed` | A build resolved for somebody brought into one case is read with a subject, or refused before anything is read |
| `make attached` | A doc comment describing something other than the declaration it sits on |
| `make confined` | Engine-specific code outside the two places allowed to hold it |
| `make readable` | Source files a text tool will not read, which every text-based check here skips in silence |
| `make unclaimed` | Every requirement is named by a design document |
| `make vendored` | Every file somebody else wrote is accounted for, under a license this tree may carry, and named in `NOTICE` where its license asks. See below |
| `make spdx` | Every source file opens with this project's copyright and an SPDX license identifier. `make spdx-fix` writes it where missing. See below |
| `make pins-check` | Every version pinned in two files still agrees |
| `make check` | Everything above. Needs npm, because the interface tier refuses rather than skipping |
| `make check-engines` | That all four engines ran, that each was the engine it claimed, and that the reserved-word list still matches what they reserve |
| `make reserved-words` | Rewrites the asked half of the reserved-word list from the running engines |
| `make weakness-names` | Rewrites the weakness names from the catalog that publishes them. In no gate, unlike the word list: the engines that one asks are pinned in CI and this authority is not, so a drift check would fail a build on the day it publishes |
| `make reserved-current` | The committed reserved-word list against what the engines answer. Inside `check-engines`, because it needs them running |
| `make check-packaging` | The container image and the Helm chart. Needs docker and helm |
| `make dist` | Every release asset, into `bin/dist`, each checked against the tag it names. Needs docker, helm and npm, because it builds the interface and gates the image. See `DESIGN-packaging.md` |
| `make docs-site` | The documentation site, built strictly. Needs mkdocs |
| `make engines-up` / `-down` / `-status` | The four database servers |
| `make measure` | Measurements rather than gates. Behind a build tag |
| `make measure-builds` | The measurement file, type-checked without being run. Inside `vet` |
| `make sbom-shape` | The reader over a full-size inventory, decompressed from a committed fixture. Inside `check` |

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
| `web/**` alone | `web-check`, `spdx` |
| Go reaching no SQL | `build`, `vet`, `lint`, `unreachable`, `readable`, `negatives`, `confined`, `granted`, `narrowed`, `attached`, `vendored`, `spdx`, `test` |
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

Three steps pass only on a commit — `openapi-current`, `web-api` and
`reserved-current` each diff a regenerated file against the last commit, so on
an uncommitted tree they report the file as stale.

Test code a tag or an environment variable guards is compiled by the gate.
A file behind a build tag is loaded by nothing an ordinary run compiles, so a
rename anywhere it reaches leaves it silently broken while the build, the vet,
the linter and CI all pass — and the one target that does pass the tag refuses
outright unless three server engines are configured, so nobody finds out. It is
vetted rather than run: `go vet` type-checks, needs no database and costs a
second, and the linter is given the tag too. A test guarded by an environment
variable nothing sets is the same gap with a different lock, and the answer is
the same: a target that sets it, inside `check`.

## CI jobs

Three, and each of the two beside the first is separate for a reason of its own
rather than for tidiness.

| Job | Holds | Why it is not a step of the first |
|---|---|---|
| Build, test and check | `engines-check`, `make check`, `check-engines`, and the bill of materials as an artifact | — |
| Container image and chart | The image built, then `check-packaging` against it | buildx and helm rather than Go, and it carries a build cache of its own |
| Documentation builds | The documentation site built | Python, and nothing else needs it |

### CI caches

| Cache | Holds | Keyed on | Saved |
|---|---|---|---|
| Go modules | Every module the tree and the pinned tools need, extracted and as downloaded | `go.sum` | When the key is new |
| Go build | The tree compiled plain and race-instrumented, its test binaries' objects, and the five tools built from source | The run, restored by prefix so a run starts from the newest | On `main` |
| Image layers | Every stage's layers | The buildkit scope | On `main` |

A pull request's run restores all three and writes none of them: what its
build would save is keyed to its own commit, which no later run builds, and a
branch's scope is read by nothing but that branch. The store holds 10 GB and
evicts what was used least recently, so a cache written for nobody is a cache
that pushes out one somebody reads.

A fresh Go build cache for this tree is 2.1 GB, 470 MB as stored; the race
flavor is 640 MB of it and the tools 840 MB. Saved on `main` alone and trimmed
by Go of anything unused for five days, it carries that many days of compiled
versions besides.

A layer written after the source is copied is keyed to the commit, so nothing
a later commit builds reuses it. The image's Go steps mount the Go build cache
rather than writing it into their layers, and the bill-of-materials tool is
fetched before the source is copied, beside `go mod download`, so its modules
sit in a layer every commit reuses. With the cache inside the layers, the
compile step's layer was 441 MB and the bill-of-materials step's 499 MB per
commit, and each run exported about 420 MB of blobs no later run read; the
same two steps are 39 MB and 131 kB, the binary and the document.

Dependency review is not a fourth job. The action needs GitHub Advanced
Security on a private repository — a paid add-on, per active committer, that
nothing else in this organization buys. Targets cover what it checks, and cover
it better: `licenses` reads the npm tree as well as the Go one, `web-audit`
scans what the interface installs, and `secrets` replaces the platform's secret
scanning. Each runs locally with one command, which an action cannot, and that
is the half of REQ-75 an action cannot meet.

Two workflows beside this one report no build of their own. `PR` is the
aggregator that waits for every check here and is the only one the ruleset
names; `Release` runs on a tag and is described in `DESIGN-packaging.md`.
Both declare `merge_group:` as this one does — a workflow that does not
contributes no check to a queue entry, and the aggregator cannot tell that
from one that has not started.

The first job runs one target, not a list of them. `make check` is the
definition of what CI checks, so a target added to it is run by CI without
anybody remembering to add a step.

Naming targets individually is what makes the two drift. Jobs listing their
targets by hand leave targets `make check` runs in no job, so the rule that
local and CI run the identical command is written down, believed and false —
including for the check that no invented name collides with a word an engine
reserves, which is a non-negotiable.

Jobs that declare nothing but a checkout and a Go setup are one job. The
interface, static analysis, vulnerabilities and licenses, the API document and
the bill of materials share a runner image, a toolchain and a module cache, and
declare no services and no conditions: separate, they are that many clones and
toolchain restores doing one machine's worth of work, and parallelism is all
that folding them costs.

A composite action is not needed. One Go setup is left in the workflow, so an
action abstracting it would have a single caller, and a reusable workflow runs
on a runner of its own — it re-clones and re-installs, which organizes the file
and keeps the cost.

Publishing documentation is a workflow of its own, not this one's fourth job. It
runs on `main` alone, writes to the repository, and publishes rather than
checks.

## Interface checks

| Tool | Covers |
|---|---|
| `tsc` | Strict, with unused locals and parameters, unchecked indexed access and verbatim module syntax |
| ESLint | Only what `tsc` has no view of. The rules of hooks are the reason it is present |
| Prettier | Formatting, for TypeScript and CSS. The counterpart to `gofmt` |
| Stylelint | CSS correctness: unknown properties, duplicate selectors, notation. Nothing about whitespace |
| `npm run classes` | Three questions about class names, below |

Formatting belongs to one tool. Stylelint's whitespace rules are off rather than
left to disagree with Prettier.

ESLint is deliberately narrow. A second opinion about style is noise beside a
formatter, and a rule that fires on working code teaches people to read past the
output. What it carries is the hook rules, which catch an impure read during
render, a dependency list that makes an effect run every time, and a value
assigned and never used.

One rule reports rather than refuses: writing state from an effect. The fix is
to remount with a key, which changes how a component mounts rather than what it
does, so each has to be driven in a browser.

## Class-name checks

A class name this project defines that Tailwind also defines. Tailwind is
imported wholesale, so it emits a utility rule for any class name in the source
it recognizes. Where that name is also defined here, both rules apply and
Tailwind's wins for the properties it sets. Nothing fails: a column with
`class="col fixed"` picks up `position: fixed` and leaves the grid.

The set is derived rather than listed. Every class this stylesheet defines a rule
for is put to Tailwind's compiler, and anything it answers for is a collision. A
utility Tailwind adds in a later version is caught on the next run.

A rule that styles nothing. Matched against the whole source rather than against
`className=`, because class names are built as well as written: `col ${kind}`
puts a modifier in the markup that appears nowhere as a literal. The check is
deliberately weak — it finds a name mentioned nowhere at all, and stays quiet
otherwise. Names from a charting library or the markdown renderer's `language-`
prefix are excluded.

A class applied to an element that nothing styles. The mirror of the question
above, and the one that catches an element rendering with no rule at all: a
label with no fill takes the browser's default, which on a dark canvas is
invisible, and a state word with no rule renders in the same grey as the state
that means the opposite. Names Tailwind emits a rule for are not the subject and
are excluded by asking its compiler, which is the same weakness the collision
check lives with — a name that happens to be a utility passes either way.

Only names written as literals are read. A class assembled entirely from an
interpolation produces no token, so this stays quiet rather than reporting
something it cannot see.

## Database engines

The suite runs against SQLite alone unless pointed at real servers, and a
skipped engine passes. A green run does not mean four engines agreed; it means
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
| SQLite | A copy of a template migrated once per binary, and a connection of its own | Not needed — each test holds its own file |
| The three servers | The package's own database on the server, through one pool every test in the binary shares | By deleting from the tables that hold rows |

The pool on a server is shared because a PostgreSQL connection is a process on
the server that starts knowing nothing of the schema. Its first statement over
the fifty-odd tables costs 43 ms, and the same statement on a warm connection
3.4 ms. With a pool per test, every test paid the first: the API package spent
90 s on PostgreSQL that way and spends 48 s with one pool. Tests in a package
run one after another on a server, so the pool carries nothing from one test to
the next that the emptying does not remove.

Each test gets a query builder of its own over the shared pool. A test may add a
query hook to count its statements, and a hook on a shared builder goes on
firing in every later test — alongside that test's own writers, which the race
detector reports.

A package whose tests start from the same rows declares them once, as a seeded
template: a function that fills a migrated, empty database and returns what a
test needs to reach the rows, such as an identifier or a secret shown once.

| Engine | When the seed runs |
|---|---|
| SQLite | Once per binary, against the template, before the first copy |
| The three servers | Per test, after the package's database is emptied |

What the seed returns on SQLite is one value shared by every test copying the
template, and those tests run beside each other, so a test reads it and does
not write to it. The API package's fixture is two products and eighteen people
with their claims and grants, about sixty transactions; run per test that was
27% of the package's processor time under the race detector on two cores, and
as a seeded template it is a file write.

A server database is kept between runs and reused. Applying the migrations is
nearly the whole cost of a server engine on a disk — 20.9 s on MySQL and 18.9 s
on MariaDB, once per package per engine — and none of it tests anything the
migration tests do not. A server CI starts is new every run, so there it keeps
nothing and builds every schema; the runner's disk makes that cheaper than a
workstation's, and the migrations package takes 25 s there against 109 s.

What makes reuse safe is the name. Below 1.0 a schema change edits what
declares the thing rather than adding a migration beside it, so the applied
version does not move and only the content of the migrations tells one
schema from another. The name therefore carries a fingerprint of the migration
sources: an edited migration names a different database rather than reusing a
stale one, and the databases the older fingerprints named are dropped as the new
one is created, so a server does not accumulate them. A kept database is emptied
before the first test sees it.

The race detector runs on SQLite alone. A Go data race does not vary by database
engine, and the detector's cost is in-process work — which is most of what
SQLite spends and almost none of what a server engine does.

| `internal/httpapi`, one engine | With the detector | Without |
|---|---|---|
| SQLite | 73.6 s | 10.1 s |
| PostgreSQL | 59.6 s | 33.5 s |
| MySQL | 18.5 s | 12.0 s |
| MariaDB | 16.9 s | 12.0 s |

The detector is a property of the binary and cannot be turned on for one
subtest, so `test-all` is two runs: SQLite with it, the three servers without.

A race-instrumented binary sleeps before it exits, so that a goroutine still
running can report a race first. The race pass sets that sleep to 100 ms. The
default of one second is paid by every test binary: 1.02 s against 0.015 s for
a package whose tests take milliseconds, and the better part of a minute across
the tree on a runner that runs the pass one package at a time. 100 ms keeps a
window for a goroutine mid-operation; nothing in the tests leaves one running
on purpose.

The two run at once. They share no engine, so neither can see the other's rows,
and they are bottlenecked on different things — the detector is in-process work
and the server pass spends its time waiting on a socket — so each fills what the
other leaves idle. Each takes half the cores, so the number of test binaries
alive at once is what a single pass has, and the peak memory falls rather than
rises: 119 s and 3.4 GB run one after another, 100 s and 1.5 GB run together,
on twelve cores with everything warm.

Each pass labels its own lines. Held and printed at the end, a run says nothing
for the whole of it — on a slow machine a quarter of an hour of a log that looks
stopped — and interleaved without labels, two runs of fifty packages are two
answers to "did it pass" with no way to tell which said what. A failure in
either fails the target, which is checked by breaking one pass at a time and
watching it go red.

`OPENPSIRT_TEST_ENGINES` narrows which engines a run touches, and `test` and
`test-race` both set it to `sqlite`. The pool's idle reaper, the migration lock
and the version floor open connections themselves rather than through `dbtest`,
so a copy of the rule in each is a copy that reads its URL without consulting
the variable — and then the quick loop and the race run open three servers,
failing on the day the servers are stopped in a way that reads as a code
regression rather than a stopped container.

The rule lives in `dbtest/engines`, a package below both `dbtest` and
`migrate`. The migration lock's test is an internal test of `migrate`, which
`dbtest` depends on, so it cannot reach a rule held in `dbtest` and a second
copy of the parsing is the alternative.

Tests within a package run beside each other when SQLite is the whole run. That
is the only run where each test already holds a database nothing else can reach;
on a server the package has one database and its tests empty it between
themselves, so two at once would clear each other's rows. A test that changes
something the whole process shares — an environment variable, the working
directory — says so and runs alone.

Together: one minute fifteen against warm servers and two minutes forty-five
against cold ones, from four minutes four seconds.

## Commit durability

A test database is created by the harness and dropped by a later run, and a
crash part-way through a suite is answered by running the suite again. The
durability a commit waits for protects nothing here, and it is most of what a
run costs.

| Engine | Setting | Where it is asked for |
|---|---|---|
| SQLite | `synchronous` off | A pragma on every test connection `dbtest` opens; `dbtest.Racing` builds its own handle and keeps the default |
| PostgreSQL | `synchronous_commit` off | The connection string, so the session gets it and the server is untouched |
| MySQL, MariaDB | `innodb_flush_log_at_trx_commit` and `sync_binlog` zero | The server, once per engine per binary — both are global on this protocol, so there is no session to ask, and the change outlives the run for every database on that server |

Nothing a test can observe changes. The settings govern what survives a crash,
not what a statement returns, what a transaction sees, or which constraint an
engine enforces.

| Every package, one engine | Durable | Relaxed |
|---|---|---|
| PostgreSQL | 90 s | 60 s |
| MySQL | 59 s | 12 s |
| MariaDB | 19 s | 12 s |
| The three together | 240 s | 77 s |

The saving belongs to the storage underneath rather than to the engines.
Containers on a workstation pay the durable figures above. The servers a
GitHub runner starts pay little enough that the whole server pass does not
move: 412 s against 413 s, where the variance between two runs of the same
tree is 5 s to 10 s on each of the large packages. The configuration this
reaches is therefore a server somebody else started, which is the one
`make engines-up` cannot pass a command line to.

The harness asks, rather than the command line the server was started with. A
server a run meets is not always one this repository started: `make engines-up`
passes the same intent at startup, which also reaches the settings an engine
accepts only there, and a workflow declaring a service container has no command
line to pass. Asking from the connection reaches both.

The settings govern commits, and a schema change syncs the files it creates
whatever they say. So a server `make engines-up` starts keeps its data
directory in memory, which removes the disk from building a schema as well as
from committing to it. The CI services keep theirs on disk: a runner's memory
is what the suite runs in, and its disk pays little for a schema change.

| Building the schema, one database, a workstation | On disk | In memory |
|---|---|---|
| PostgreSQL | 0.49 s | 0.45 s |
| MySQL | 20.9 s | 0.79 s |
| MariaDB | 18.9 s | 0.17 s |

The server pass over every package, six at once, went from 516 s to 246 s of
package time with the pool above and the data in memory, where the 516 s reused
databases migrated by an earlier run and the 246 s migrated every one. A
container stopped and started again has lost its databases, and the harness
migrates new ones.

A connection that may not set a global leaves the server as it is and the suite
runs slower. A test reads the setting back from the session it was handed and
fails where it is durable on a connection that could have changed it, which
separates a harness that stopped asking from a server nobody may configure.

## Pinned pairs

A version written in two files is a version somebody moves in one of them: the Go
toolchain the container builds with against the one the module declares, the Node
the image uses against the one every workflow runs, the SBOM generator in the
image against the one the SBOM target invokes, and the Python the documentation
closure was resolved on against the one the workflows build it with.

A check of its own rather than part of the engine check: that answers what the
tests run against, this answers what the release is built from. An image
carrying two defaults for the version passed in is what it catches — a build
with none then reports `dev` in the binary and `0.0.0` in its own inventory.

The Go patch counts. A floating base image and a comparison truncated to the
minor cannot tell one patch apart, so a tarball and an image built from the same
commit are a release built twice by two toolchains with the gate green. The
image names the patch `go.mod` declares and the check compares the whole
version.

| What that costs | What answers it |
|---|---|
| The image no longer picks up a Go release by itself | Dependabot watches the images and a bump arrives as a pull request |
| A pinned toolchain goes stale between bumps | `govulncheck` reports standard-library vulnerabilities, and now reports them about the toolchain both artifacts are built with rather than about one of the two |

## Hash pinning per ecosystem

| Ecosystem | What names the bytes |
|---|---|
| Go | `go.sum`, through the checksum database |
| Node | `package-lock.json`, by integrity |
| Python, for the documentation | `docs/requirements.txt`, a lock with a hash for every package in the closure, installed with `--require-hashes` |
| The scanner and the cataloger | A version and a per-architecture hash in the image |
| Actions | A commit, never a tag |

The Python closure is the one that runs beside a token that can write to the
repository. Pinning the direct packages and not the closure they pull in leaves
a republished transitive release executing on the next push.

Direct versions are written in `docs/requirements.in` and the lock beside it is
generated, never edited:

```
pip-compile --generate-hashes --output-file docs/requirements.txt docs/requirements.in
```

`pins-check` asks that every package in the lock carries a hash, that each
direct version is the one the lock resolved, that every workflow installing it
passes `--require-hashes`, and that they agree on one Python — the lock was
resolved on one, and a second would resolve a different closure.

A hash-pinned install fails closed when an upstream republishes, which is a
refusal to install rather than something executing unnoticed, and it is
answered by regenerating the lock in a commit somebody reviews.

## Static analysis

Rule selection lives in `.golangci.yml` and nowhere else. Two scopes only: a
rule gates, or it is advisory. There is no third scope for grandfathering a
backlog (REQ-75).

The linter set is tuned rather than enabled wholesale. Documentation rules are
off; error checking excludes the cleanup-path functions conventionally ignored.

The linter must be built with a Go release at least as new as the code, or it
cannot read the compiler's export data and fails on every file with a message
about import versions. The pinned version moves when the language version does.

## Gate inputs

Every gate program written here walks the repository through one reader, which
holds the default set of directories none of them read: the version history, a
local run's scratch, somebody else's code, and the three output directories,
whose contents were built from what is checked anyway.

Each caller names what it adds, at the call site, with the reason beside it. The
five Go gates add the interface, which is TypeScript; the text-encoding gate
adds a vendor directory and deliberately does not add the interface, because a
byte that makes a text tool skip a file is not a Go question.

| Rule | |
|---|---|
| **A walk that reaches nothing refuses** | An empty result is what "nothing is wrong" looks like and what "I read nothing" looks like. No caller can tell those apart from a count of zero, so the reader answers an error rather than a silence |
| **What is counted is what the caller kept**, not what it was shown | A count of visits is held above zero by any file at all, so the refusal above could never fire for a gate that reads one kind of file |
| **Every gate says how much it read** | The count is beside the all-clear, so a run that quietly stopped reading part of the tree does not look like a run that read all of it |
| **A directory is matched by name at any depth**, not by path prefix | Which is what a caller adding one means, and it is how nested dependency directories are covered |
| **A change here takes the whole gate** | These programs decide what every other check looks at, and no narrower tier covers that: the reader holds no queries and registers no operation, so it would otherwise be classified as ordinary code and skip the checks it governs |

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

Both ecosystems, one allowlist. The interface is built into the binary, so what
npm installs ships exactly as a Go module does. `make licenses` runs both
halves against the same `ALLOWED_LICENSES`, passed in rather than repeated, and
dev dependencies are unrestricted on both sides because a build tool binds
whoever builds rather than whoever installs.

| Exception | Why |
|---|---|
| `@fontsource/*` under OFL-1.1 | The license fonts are published under. What it withholds is selling the fonts on their own, which is not something a shipped application does |
| `argparse` under PSF-2.0 | A port of Python's argparse carrying the original's license. Permissive, and compatible |

An SPDX expression is evaluated rather than matched: `MIT AND ISC` needs both
allowed and `(MPL-2.0 OR Apache-2.0)` needs either. Treating the string as a
name refuses both, and adding the strings to the allowlist accepts every other
expression spelled that way.

### Copied files

What is copied into the tree rather than imported is checked by `make
vendored`: a version suite taken from another project, a specification's
example document, a publisher's advisory, a table transcribed from a reference
implementation, a generated catalog. Each is in one list, with where it came
from and the license its source states.

| Rule | |
|---|---|
| A file is found in the tree, then looked for in the list | Every file under a `testdata` directory, and every file carrying a copyright line that is not this project's, a license identifier, a document's data license, or a comment saying `NOTICE` records it. A file copied in without a line in the list fails the gate |
| This project's own header is not a mark | A file carrying this project's copyright is ours, and the identifier beside it naming this tree's own license says nothing more. Any other identifier in it is still somebody else's terms |
| Found broadly, and a file written here is listed as ours | A file the search misses is one nobody is asked about. A fixture written here costs a line saying so |
| Not searched | `NOTICE` and `LICENSE`, which are the statements; markdown, which is prose about the tree; a file that is not text; and the gate's own source and the list it reads, which spell every mark it looks for |
| Held to a license this tree may carry | The dependency allowlist, and beside it the licenses data is published under: a dedication to the public domain, CC-BY-4.0, and the weakness catalog's own terms. An expression is evaluated as the dependency check evaluates one |
| Named in `NOTICE` where the license asks for attribution | Every license here but a public-domain dedication asks for it. A file under one that `NOTICE` does not name fails the gate |
| Every path `NOTICE` names is in the tree and held as somebody else's | The other direction, so a file removed or renamed leaves no attribution pointing at nothing |
| What a file's license is, is read by a person | A data file states its license in its own words where it states one at all. The list is where somebody writes down what they read, and the gate holds them to having written it |

### License headers

Every source file opens with this project's copyright and an SPDX license
identifier, checked by `make spdx` and written where missing by `make
spdx-fix`.

    // Copyright Nexthop Systems Inc.
    // SPDX-License-Identifier: Apache-2.0

| Rule | |
|---|---|
| Source is Go, TypeScript, JavaScript, CSS, shell, Python, a makefile and a Dockerfile | The files a license scanner reads as code. Markdown, configuration and data carry none |
| Each writes it in its own comment | Two slashes, a slash-star pair per line in CSS, and a hash elsewhere |
| It comes first, after only what has to | An interpreter line, and a Dockerfile's parser directives, which are read only from the top. A blank line follows it, so a Go file's package comment stays attached to the package |
| A file carrying somebody else's work states their terms beside this tree's own | The expression is this license joined with the one the list of copied files holds for it, so the two gates cannot disagree about a file |
| A fixture and a file a third party's tool writes whole carry none | A fixture is data the copied-files list accounts for. A generated file loses the header every time it is written; the generators that are this project's write it themselves |
| A wrong header is reported and not rewritten | Which of the two is right is a person's to read |
| No year | The dated notice is in `NOTICE`. A year per file is either touched every January or wrong, and a wrong one reads worse than none |

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
and the interface's assets do too. None of them reads anything from the
database about what this deployment holds (REQ-43).

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

## Action pinning

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
| Dependency graph, via Dependabot alerts | Being told about a vulnerable dependency between changes | A dependency goes bad and nothing says so until somebody looks |
| Actions pinned to a SHA | The section above | A tag somebody else controls executes here |
| Pages, serving the `gh-pages` branch | Documentation publishing | The workflow succeeds and nothing is served |

Private and public differ, and what differs is paid for. Secret scanning, push
protection and dependency review are free on a public repository and are
Advanced Security products on a private one, billed per active committer across
the repositories that enable them. None is enabled here: the gate runs `make
secrets`, `make licenses` and `make web-audit` instead, which cost nothing and
run locally. Dependabot alerts are free either way and are on.

What is genuinely lost by not buying them is history: a credential committed
and later removed is still in the objects, and scanning the working tree
cannot see it. Push protection would also refuse the push that put it there.
Both are worth reconsidering when the repository goes public, where they are
free.

A private Pages site is served only to accounts with read access, at a
generated address rather than at the organization's.

## Limits

| | |
|---|---|
| Branch protection is not enforced | The gate runs on every pull request but nothing blocks a merge, which is the state REQ-75 warns about. Deliberate for early development, and it needs revisiting before outside contributions |
| The documentation workflow publishes one set, `main`, as the default | Publishing a tag under its version and moving a `latest` alias belongs with a release process that does not exist. The versioning machinery is in place |
| The install and operate guides are not written | Both are about a release — how to get a version, how to move between them, what to back up before an upgrade — and there is no release process, so a guide written now would describe the demo target and the development database |
| The gate and CI run the same commands | Written twice, neither copy a superset of the other, a reviewer running the gate and a merge being blocked check different things |
| A check needing a running server refuses rather than skips | A skipped test passes, and "the suite is green" and "the suite ran" are two different facts behind one command |
| `README.md` and `docs/index.md` are compared | Neither can include the other, and the same list maintained twice drifts |
