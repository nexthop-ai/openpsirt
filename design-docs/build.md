# Build and validation

Repository layout, the make targets, the gate, CI, and what stops a change
reaching `main`.

Satisfies REQ-43, REQ-61, REQ-62, REQ-63, REQ-75.

## Contents

- [Layout](#layout)
- [Make targets](#make-targets)
- [Gate tiers](#gate-tiers)
- [CI jobs](#ci-jobs)
- [Gate inputs](#gate-inputs)
- [Static analysis](#static-analysis)
- [The API document](#the-api-document)
- [Probes](#probes)
- [The review checklist](#the-review-checklist)
- [Repository settings](#repository-settings)
- [Limits](#limits)

## Layout

| Path | Holds |
|---|---|
| `cmd/openpsirt/` | The binary: flag parsing, configuration, server lifecycle |
| `cmd/openpsirt-upload/` | The upload client a pipeline runs. See `design-docs/analysis.md` § Upload client |
| `internal/version/` | What this build is, injected at link time |
| `internal/config/` | Settings, read from the environment with working defaults |
| `internal/httpapi/` | The HTTP surface: the router, the middleware in front of every route, sign-in, the served interface, and every area's operations registered into the one description the API document is generated from. See `design-docs/api.md` § File organization |
| `internal/httpapi/core/` | What every API area shares: handler dependencies, resolving a caller, declared rights, refusal sentences, and bodies more than one area answers with |
| `internal/httpapi/scansapi/`, `internal/httpapi/findingsapi/`, `internal/httpapi/assignapi/`, `internal/httpapi/triageapi/`, `internal/httpapi/analyticsapi/`, `internal/httpapi/advisoryapi/`, `internal/httpapi/adminapi/` | The operations, one package per area: inventories arriving, findings, handing work out, decisions, reports, advisories, administration |
| `internal/httpapi/httpapitest/`, `internal/httpapi/refusaltest/` | The shared test harness, a server over a seeded cast, and the checks each area runs over its refusal mappers |
| `internal/database/` | Opening, identifying and validating a database. See `design-docs/database.md` |
| `internal/database/migrate/` | The migration runner and its locks |
| `internal/database/migrate/migrations/` | The migrations |
| `internal/schema/` | Applies this application's schema, so that using the runner registers the migrations |
| `internal/dbtest/` | Runs a test against every database available to it |
| `internal/catalog/` | Products, branches and tags, and variants. See `design-docs/data-model.md` |
| `internal/ingest/` | Arriving scans. See `design-docs/ingest.md` |
| `internal/queue/` | Durable background work. See `design-docs/queue.md` |
| `internal/sbom/`, `internal/scanner/` | Reading an inventory and scanning it. See `design-docs/ingest.md` |
| `internal/docread/` | Reading somebody else's document as a bounded stream, for every reader of one. See `design-docs/ingest.md` |
| `internal/sarif/` | Reading an analyzer's SARIF and placing its results in the checkout. See `design-docs/analysis.md` |
| `internal/series/` | Runs of one analysis across builds: order, comparability, and what each saw. See `design-docs/kinds.md` |
| `internal/analysis/` | Applying an analyzer's run to its build as findings of the analysis kind. See `design-docs/analysis.md` |
| `internal/sourcelink/` | What a product says about its repositories, and the source addresses built from it. See `design-docs/analysis.md` |
| `internal/uploadclient/` | The SARIF the upload client sends, built from an analyzer's output and the checkout. See `design-docs/analysis.md` § Upload client |
| `internal/graph/`, `internal/finding/` | The dependency graph and what a scan found. See `design-docs/data-model.md`, `design-docs/findings.md` |
| `internal/filed/` | The one spelling of a record filed under an issue read as another. See `design-docs/findings-issues.md` § Merged issues |
| `internal/rating/` | A product's own rating of an issue as spelled in a query, where both sides of the graph may say it. See `design-docs/findings-severity.md` |
| `internal/cvss/` | Scoring a CVSS 3.0, 3.1 or 4.0 base vector and its band, with no database. See `design-docs/findings-severity.md` |
| `internal/triage/`, `internal/advisory/` | Decisions, approvals, and the CSAF document. See `design-docs/triage.md` |
| `internal/access/`, `internal/signin/` | Subjects and sign-in. See `design-docs/access.md` |
| `internal/notify/` | Notifications. See `design-docs/notifications.md` |
| `internal/weblink/` | Addresses into the interface the server hands out, held to the route table. See `design-docs/notifications.md` § Links |
| `internal/incident/` | Response windows after an incident, the notices given, and the shelf over both. See `design-docs/incidents.md` |
| `internal/markdown/`, `internal/setting/`, `internal/currency/` | Text policy, administrator settings, and upstream version lookups |
| `internal/attach/` | Files on an issue, and what may be served back. See `design-docs/attachments.md` |
| `internal/trail/` | What somebody changed about how this deployment works. See `design-docs/access.md` |
| `internal/saved/` | A kept narrowing of a list, and the decision it prepares. See `design-docs/remediation.md` |
| `internal/vex/`, `internal/publisher/` | What is decided about what a build ships, and who says so. See `design-docs/remediation.md` |
| `internal/directory/` | Issued advisories, written where another web server serves them. See `design-docs/remediation.md` |
| `internal/csaf/` | The shapes of a CSAF provider description and ROLIE feed, and the lists a provider serves; the supplier reader reads its fields under these names. See `design-docs/remediation.md` |
| `internal/publish/` | Security documents served to anybody: statements, revisions, and the pass that writes them. See `design-docs/publishing.md` |
| `internal/httpapi/published/` | The surface serving them, beside the API. See `design-docs/publishing.md` |
| `internal/signing/` | Signing what is published with the operator's key. See `design-docs/publishing.md` |
| `internal/supplier/` | Publishers whose advisories are read on a schedule, and a pass over one. See `design-docs/ingest.md` |
| `internal/upstream/` | The upstream a product trusts, and the pass reading its VEX documents. See `design-docs/upstream.md` |
| `internal/cverecord/` | The CVE record snapshot: fetching, reading, and what a record says about a version. See `design-docs/findings-closure.md` § CVE record ranges and `design-docs/ingest.md` § CVE records |
| `internal/patchbranch/` | Which branches hold a patch link's commit, the repository copies answering it, and git's outbound proxy. See `design-docs/findings-patch-branches.md` |
| `internal/vercmp/` | Ordering two versions of one package, where the ecosystem defines one. See `design-docs/remediation.md` |
| `internal/outward/` | The one HTTP client this process reaches the internet with. See `design-docs/access.md` |
| `internal/typedname/` | The one stored and matched form of a typed name. See `design-docs/data-model.md` |
| `internal/background/`, `internal/bound/` | A pass on a timer, and cutting a string to a byte or character count without splitting a character |
| `internal/redact/` | An address that may carry a credential, as text safe to log or refuse with. See `design-docs/access.md` § Secrets and logs |
| `internal/refusal/` | A sentence a caller may read, told apart from a fault whose text is withheld. See `design-docs/api.md` |
| `internal/webui/` | The built interface, embedded. See `design-docs/interface.md` |
| `internal/weakness/` | The weakness catalog's name for each identifier. See `design-docs/remediation.md` |
| `internal/docs/`, `internal/build/`, `internal/tools/` | Document checks, makefile checks, and the commands the makefile runs: the gates that are not linters, and the release, rehearsal and image-inventory tools |
| `web/` | The interface source. See `design-docs/interface.md` |
| `deploy/helm/openpsirt/` | The chart. See `design-docs/packaging-chart.md` |
| `docs/` | The published documentation site |
| `assets/` | Logo files |
| `tools/` | One module per Go tool the gate and the image run. See `design-docs/build-dependencies.md` § Tool pins |
| `Makefile` | The build, test runs, linter, gate, `check`, interface build, measurements and cleanup. Every other makefile is included after its own targets, so the first target stays the default |
| `mk/engines.mk` | The database servers the suite runs against, as containers, and `check-engines` |
| `mk/gates.mk` | The checks beside the linter and suite: vulnerabilities, licenses, inventory, credentials, the gate programs, generated files against their generators, and pinned versions against each other |
| `mk/dist.mk` | The release assets, built and checked in one directory, and the record of a release's migrations |
| `mk/packaging.mk` | The container image and chart, checked as what ships |
| `Makefile.demo` | The image and what is built from it: the seeded demo, the hot-reload loop, and the offline scanner bundle, with every variable they read. Apart from the gate half, which shares nothing with it but the docker and npm command names |

| Rule | Reason |
|---|---|
| Everything is under `internal/` | Nothing is importable by another module |
| Each makefile declares its own targets phony, and a test fails on a makefile no include names | |
| `internal/database` cannot read a setting | `internal/setting` imports it, so a bound that low comes from the environment |
| The schema's tests cannot reach the harness's table list | They are an external test package, and the list is the harness's own |

## Make targets

Every check CI runs is a `make` target, so a CI failure reproduces locally with
the same command and the same pinned tools (REQ-75).

The Go package pattern is the list `go list` gives minus `node_modules`, never
`./...`, because an npm dependency ships a Go package (`web/node_modules/flatted/golang`)
that `./...` would compile, vet, test and scan. Every tool written here skips
`node_modules` by name.

| Target | Runs |
|---|---|
| `make build` | The binary, with version information injected |
| `make gate` | The checks this change has to pass, chosen from what it touches |
| `make gate full` | All of them, whatever the change touches |
| `make test` | SQLite only, packages in parallel, cached. Seconds |
| `make test-all` | Every configured engine, uncached: the two runs below, at once |
| `make test-race` | SQLite with the race detector, tests within a package in parallel |
| `make test-engines` | The three server engines, without the detector |
| `make docs-check` | What a change to documents alone can break |
| `make lint` | Static analysis, pinned version |
| `make vet-other-os` | Type-checks the build for macOS, which compiles files a build constraint keeps off Linux, and the upload client for Windows |
| `make client-test` | The upload client's tests, uncached, as the macOS and Windows jobs run them. `make client-packages` and `make client-sources` print the lists those jobs read |
| `make govulncheck` | Known vulnerabilities in Go modules and the toolchain, failing only what the change introduced |
| `make licenses` | Shipped dependency licenses against the allowlist, Go and npm |
| `make web-audit` | Known vulnerabilities in what the interface installs, failing only what the change introduced |
| `make secrets` | Credentials in tracked files and in untracked files git does not ignore, with a pinned scanner |
| `make openapi` | Regenerates the API document from the code |
| `make openapi-current` | The committed API document against what the code generates |
| `make sbom` | This project's own CycloneDX inventory |
| `make web-check` | Interface: locked install, type check, Prettier, ESLint, Stylelint, tests with coverage, class-name checks, and the generated client against the API document. Refuses without npm |
| `make unreachable` | Exported code nothing reaches. A function, type, constant or variable is counted by package and name, a qualified reference resolving through the file's imports; a method by name alone, since its receiver type needs type information. A test counts as a caller |
| `make negatives` | A 404 built from an error's text, or given an error as a detail, which publishes whatever the error carried. Read as parsed Go, so a call spread over lines and an error under any name are one shape; the text counts read with its method, formatted from a value named like an error, or bound earlier in the same declaration |
| `make granted` | Every function reaching one grant table reaches the other: by the table's name, by a model whose struct tag binds it, by a type built from such a model as an alias or embedding, or through a package-level name whose value does. Each package-level name is judged by its own value too. The functions that legitimately ask one table are named in the gate with a reason each, and a name matching nothing fails it |
| `make narrowed` | A build resolved for somebody brought into one case is read with a subject, or refused before anything is read. A resolution bound by assignment or `var` is followed, and every value copied, collected or built from it; one used inline is not. The innermost call around a use decides |
| `make subjected` | An exported method of the finding, triage or graph store that queries and takes no subject, unless the exempt list names it with a reason. A method queries when it builds a query or calls a function of its own package that does, to a fixed point, by name. A query through another package, or a subject taken and not applied, is not seen |
| `make attached` | A doc comment describing something other than its declaration |
| `make confined` | Engine-specific code outside the two places allowed to hold it |
| `make readable` | Source files a text tool will not read, which every text check skips in silence |
| `make unclaimed` | Every requirement is named by a design document |
| `make vendored` | Every copied file is accounted for under a license this tree may carry, and named in `NOTICE` where its license asks. See `design-docs/build-dependencies.md` § Copied files |
| `make spdx` | Every source file opens with this project's copyright and an SPDX identifier; `make spdx-fix` writes it where missing. See `design-docs/build-dependencies.md` § License headers |
| `make pins-check` | Every version pinned in two files still agrees |
| `make go-version` | The Go release the image builds with, which every workflow installs |
| `make check` | Everything above. Needs npm |
| `make check-engines` | All four engines ran, each was the engine it claimed, and the reserved-word list matches what they reserve |
| `make reserved-words` | Rewrites the asked half of the reserved-word list from the running engines |
| `make weakness-names` | Rewrites the weakness names, and each weakness's primary parent in the catalog's research view, from the catalog. In no gate: the catalog is not pinned, so a drift check would fail a build on the day it publishes |
| `make cppcheck-weaknesses` | Rewrites the weakness each cppcheck check finds from `cppcheck --errorlist`, with the version asked. In no gate, since CI installs no cppcheck. `CPPCHECK` names the binary |
| `make clang-checkers` | Fails naming each clang static analyzer checker for C the weakness table has not looked at. Run against each new clang release. `CLANG` names the binary |
| `make reserved-current` | The committed reserved-word list against what the engines answer. Inside `check-engines`, which has them running |
| `make check-packaging` | The container image and Helm chart. Needs `$(DOCKER)`, docker unless set, and helm, and says which is missing |
| `make dist` | Every release asset into `bin/dist`, each checked against its tag. Needs docker, helm and npm, and refuses without them, since it builds the interface and gates the image. See `design-docs/packaging-release.md` § Release assets |
| `make release-freeze VERSION=vX.Y.Z` | The record of a release's migrations: the schema they build on every engine, each file and its digest, then the check below. Run on a branch from the head of `main` with the four engines up, landed before the tag. See `design-docs/database.md` § Release records |
| `make release-check VERSION=vX.Y.Z` | The release a tag names was frozen and the tree still ships what it froze. The release workflow runs it before building |
| `make docs-site` | The documentation site, built strictly. Needs mkdocs |
| `make engines-up` / `-down` / `-status` | The four database servers |
| `make engines-clean` | Drops the test databases no running test holds, on every configured server. See `design-docs/build-tests.md` § Test databases |
| `make measure` | Measurements, behind a build tag. Each starts from tables laid out as a fresh load leaves them and prints the layout beside its timings. See `design-docs/build-tests.md` § Measurement databases |
| `make sbom-shape` | The reader over a full-size inventory, decompressed from a committed fixture. Inside `check` |

## Gate tiers

`make gate` reads what the working tree changed and runs the tier that change
lands in, because running everything for a prose edit teaches people to skip the
gate (REQ-75). Tiers accumulate: a commit carrying a design document and a query
runs both.

| Touched | Adds |
|---|---|
| `*.md` alone | `docs-check`, `unclaimed`, `pins-check`, `readable`, `secrets` |
| `web/**` alone | `web-check`, `spdx`, `readable`, `secrets` |
| the interface's manifest, lockfile or source | `licenses` as well as the interface's tier |
| the interface's route table | the Go tier as well, because a Go test holds the server's links to it |
| Go reaching no SQL | `build`, `lint`, `vet-other-os`, `unreachable`, `readable`, `negatives`, `confined`, `granted`, `narrowed`, `subjected`, `attached`, `vendored`, `spdx`, `pins-check`, `sbom-shape`, `secrets`, `test` |
| a query, the schema, a migration, or the shared test harness | `reserved`, `test-all`, `check-engines` |
| Go the API document is generated from: any file of the registering package, and any declaring a field with a description | `openapi-current`, `web-api` |
| `go.mod` or `go.sum` | `govulncheck`, `licenses`, `sbom`, and the engines tier |
| a tool's module under `tools/`, its source included | the whole gate, because the gate runs that tool |
| a gate program's shared repository reader | the whole gate (§ Gate inputs) |
| anything else, or nothing | the whole gate |

| Rule | Reason |
|---|---|
| A program chooses the tier | It reads the same change the same way every time |
| A path nobody classified takes the whole gate | The makefile, the container, the chart, an asset, a fixture. A tier that quietly omits one costs more |
| A Go file is classified by what the whole file holds, never the edited lines | A change anywhere in a file of queries can move what a query returns |
| A file takes every tier it lands in | A route file holding a query is API input and portability work at once |
| Every tier a change reaches alone scans for secrets | A credential pushed is in the remote's history before CI reads it |
| Every target `check` runs is chosen by some narrow tier | A test holds the join |
| `docs-check` tests every package whose tests read a document | A test holds the list to the tests that climb out of their package to a `.md` file |
| A clean tree takes the whole gate | Before a push it is carrying committed work |
| `test-all` replaces `test` | The same tests, on four engines |
| Local and CI run the identical command | Otherwise "it passed locally" means nothing |
| `openapi-current`, `web-api` and `reserved-current` pass only on a commit | Each diffs a regenerated file against the last commit |
| Test code behind a build tag is linted, with the tag passed | Nothing an ordinary run compiles loads it, and the target that runs it refuses without three server engines, so a rename leaves it broken with every check green. The linter type-checks it with no database |
| A test behind an environment variable has a target inside `check` that sets it | A variable nothing sets is the same gap |

## CI jobs

| Job | Holds | Separate because |
|---|---|---|
| Build, test and check | `engines-check`, `make check`, `check-engines`, and the bill of materials as an artifact | — |
| Container image and chart | The image built, then `check-packaging` against it | buildx and helm, with a build cache of its own |
| Documentation builds | The documentation site built | Python, which nothing else needs |
| Upload client on macOS and Windows | `client-test` on each system, after a Linux step compares the change against `client-sources` | The client runs on a build host, and only those systems show its paths and line endings as a pipeline there does |

| Rule | Reason |
|---|---|
| The first job runs `make check`, never a list of targets | `check` is the definition of what CI checks, so a target added to it runs in CI. Hand-listed jobs leave targets in no job, the reserved-word check among them |
| Jobs declaring only a checkout and a Go setup are one job | Separate, they are as many clones and toolchain restores for one machine's work |
| No composite action or reusable workflow | One Go setup remains, and a reusable workflow re-clones and re-installs on a runner of its own |
| The macOS and Windows jobs run only when a client source moved | Such a runner costs several Linux ones, and nothing else reaches the client |
| The source list is what reaches the client | A test in `internal/build` fails on a package the client imports that `client-sources` lacks. The list holds the fixtures the client's tests read from another package, and the Dockerfile, whose `golang` tag is the runners' Go release |
| No make on Windows | The Linux step prints the package list and the Go release, and both jobs run `go test` on them |
| A skipped job satisfies the merge check | The aggregator waits for checks to pass or be skipped. A queue entry and a pull request compare against their own base |
| `PR`, the aggregator, is the one check the ruleset names; `Release` runs on a tag (`design-docs/packaging-release.md` § The release procedure) | Both report no build of their own |
| Every gating workflow declares `merge_group:` | A workflow without it contributes no check to a queue entry, which the aggregator cannot tell from one not started |
| Publishing documentation is a workflow of its own | It runs on `main` alone, writes to the repository, and publishes |
| Dependency review is not run | The action needs GitHub Advanced Security on a private repository, a paid add-on per committer. `licenses`, `web-audit` and `secrets` cover it, and each runs locally with one command, which an action cannot (REQ-75) |

### CI caches

| Cache | Holds | Keyed on | Saved |
|---|---|---|---|
| Go modules | Every module the tree and the pinned tools need, extracted and as downloaded | `go.sum` and each tool's under `tools/` | When the key is new |
| Go build | The tree compiled plain and race-instrumented, test binaries' objects, and the tools built from source | The run, restored by prefix so a run starts from the newest | On `main` |
| Linter results | The linter's analysis of each package, by the content it read | The run, restored by prefix | On `main` |
| Image layers | Every stage's layers | The buildkit scope | On `main` |

| Rule | Reason |
|---|---|
| A pull request's run restores all four and saves none | What it would save is keyed to a commit no later run builds, and the 10 GB store evicts the least recently used |
| The build and linter caches are saved holding only what the run read | Before the checks every restored entry is moved two hours back, and after them every entry no read moved is deleted; both tools refresh an entry's time only past an hour old. A cache saved as the run left it carries every version of the tree compiled on `main` in five days: 2.87 GB against 683 MB |
| The linter's results are keyed by each package's content | One changed file costs 9 to 12 s against 42 s with no results |
| The image's Go steps mount the Go build cache, never write it into a layer | A layer after the source copy is keyed to the commit. 441 MB and 499 MB per commit became 39 MB and 131 kB |
| The bill-of-materials tool is fetched before the source is copied, beside `go mod download` | Its modules sit in a layer every commit reuses |

`design-docs/build-measurements.md` § CI caches has the runs.

## Gate inputs

Every gate program written here walks the repository through one reader. Its
default skip set is the version history, a local run's scratch, a local tool's
working directory, which holds whole worktree copies, vendored code, and the
three output directories. Each caller names what else it skips at the call
site, with the reason: the Go gates skip the interface, which is TypeScript, and
the text-encoding gate skips a vendor directory and reads the interface, since a
byte that makes a text tool skip a file is no Go question.

| Rule | Reason |
|---|---|
| A walk that reaches nothing refuses | "Nothing is wrong" and "read nothing" are both zero |
| What is counted is what the caller kept, never what it was shown | A count of visits is held above zero by any file at all |
| Every gate prints how much it read beside the all-clear | A run that stopped reading part of the tree looks like one that read all of it |
| A skipped directory is matched by name at any depth | Nested dependency directories are covered |
| A change to the reader takes the whole gate | It decides what every other check reads, and holds nothing a narrow tier would catch |

## Static analysis

| Rule | Reason |
|---|---|
| Rule selection lives in `.golangci.yml` alone, in two scopes: a rule gates or is advisory | No third scope grandfathers a backlog (REQ-75) |
| The linter set is tuned: documentation rules off, and error checking excluding the cleanup-path functions conventionally ignored | |
| The linter is the vet: its `govet` runs every `go vet` analyzer and one more, over test files and the `measure`-tagged file | The same analysis twice was 50 s of a two-core runner |
| A test holds that configuration | `govet` enabled with no settings narrowing it, test and generated files not excluded, no exclusion naming `govet` or a test file, the `measure` tag passed. The linter skips generated files by default, so the configuration turns that off for every linter |
| The linter reports one issue per line | Two problems on one line appear one at a time |
| The linter is built with a Go release at least as new as the code | Otherwise it cannot read the compiler's export data and fails on every file (`design-docs/build-dependencies.md` § Pinned pairs) |

## The API document

| Rule | Reason |
|---|---|
| Generated from the operations registered in `internal/httpapi` and its areas, never written by hand (REQ-61) | |
| CI regenerates it and fails where the committed copy differs | What each operation asks of a caller rides on it (REQ-62), so "who may call this" is checked by the same diff |
| The application serves the document itself, authenticated like every route, and nothing that renders it (REQ-63) | |

## Probes

| Rule | Reason |
|---|---|
| `/healthz` and `/readyz` answer without authentication and report only whether the process is up | A container probe cannot sign in |
| They are outside the documented API and never grow a body describing contents | |
| The sign-in paths and the interface's assets also answer without a credential, and read nothing about what the deployment holds (REQ-43) | The published security documents are the one surface that does, as anybody (`design-docs/publishing.md`) |

`design-docs/packaging-chart.md` § Chart probes says how the chart uses them.

## The review checklist

The checklist in `AGENTS.md` is worked through on every review (REQ-75). The
pipeline does not enforce it: what a machine can check, CI checks, so the
checklist holds only what a machine cannot decide.

## Repository settings

None of these is in a file, and an absent one fails somewhere far from itself.

| Setting | Needed by | Symptom when off |
|---|---|---|
| Every change through a pull request, no direct push to `main` | The gate meaning anything | A commit reaches `main` having passed nothing |
| Merge queue, squash, `ALLGREEN` | Landing what was tested | A pull request green against a `main` that has moved |
| One required check, `Merge Status` | Every other check | A workflow added later gates nothing until the ruleset is edited |
| Dependency graph, via Dependabot alerts | Hearing of a vulnerable dependency between changes | A dependency goes bad unreported |
| Actions pinned to a SHA (`design-docs/build-dependencies.md` § Action pinning) | Running only reviewed action code | A tag somebody else controls executes here |
| Pages, serving the `gh-pages` branch | Documentation publishing | The workflow succeeds and nothing is served |

| Rule | Reason |
|---|---|
| Secret scanning, push protection and dependency review are not enabled | On a private repository each is an Advanced Security product billed per committer. `make secrets`, `make licenses` and `make web-audit` run instead, free and local. Dependabot alerts are free and on |
| A private Pages site is served only to accounts with read access, at a generated address | |

## Limits

| Limit | Detail |
|---|---|
| History is not scanned for credentials | A credential committed and later removed stays in the objects, and push protection would have refused the push. Both are free once the repository is public, and worth enabling then |
| The gate and CI run the same commands | Written twice, neither copy a superset of the other, a reviewer's gate and the merge block check different things |
