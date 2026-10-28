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
| `cmd/openpsirt/` | The binary: flags, configuration, server lifecycle |
| `cmd/openpsirt-upload/` | The upload client. See `design-docs/analysis-client.md` § Upload client |
| `internal/version/` | Build identity, injected at link time |
| `internal/config/` | Settings from the environment, with defaults |
| `internal/httpapi/` | Router, middleware, sign-in, the served interface, and the operation registry the API document is generated from. See `design-docs/api.md` § File organization |
| `internal/httpapi/core/` | What every API area shares: handler dependencies, caller resolution, declared rights, refusal sentences, shared bodies |
| `internal/httpapi/scansapi/`, `internal/httpapi/findingsapi/`, `internal/httpapi/assignapi/`, `internal/httpapi/triageapi/`, `internal/httpapi/analyticsapi/`, `internal/httpapi/advisoryapi/`, `internal/httpapi/adminapi/` | One package per area: inventories, findings, assignment, decisions, reports, advisories, administration |
| `internal/httpapi/httpapitest/`, `internal/httpapi/refusaltest/` | The shared test server over a seeded cast, and the refusal-mapper checks |
| `internal/database/` | Opening, identifying and validating a database. See `design-docs/database.md` |
| `internal/database/migrate/` | The migration runner and its locks |
| `internal/database/migrate/migrations/` | The migrations |
| `internal/schema/` | Registers this application's migrations with the runner |
| `internal/dbtest/` | Runs a test against every available database |
| `internal/catalog/` | Products, branches and tags, variants. See `design-docs/data-model.md` |
| `internal/ingest/` | Arriving scans. See `design-docs/ingest.md` |
| `internal/queue/` | Durable background work. See `design-docs/queue.md` |
| `internal/sbom/`, `internal/scanner/` | Reading and scanning an inventory. See `design-docs/ingest-parsing.md`, `design-docs/ingest-scanner.md` |
| `internal/docread/` | A third party's document as a bounded stream. See `design-docs/ingest-parsing.md` |
| `internal/sarif/` | Reading SARIF and placing results in the checkout. See `design-docs/analysis-source.md` |
| `internal/series/` | Runs of one analysis across builds. See `design-docs/kinds.md` |
| `internal/analysis/` | An analyzer's run applied as findings. See `design-docs/analysis.md` |
| `internal/sourcelink/` | A product's repositories and the source addresses built from them. See `design-docs/analysis-source.md` |
| `internal/uploadclient/` | The SARIF the upload client builds. See `design-docs/analysis-client.md` § Upload client |
| `internal/graph/`, `internal/finding/` | The dependency graph and findings. See `design-docs/data-model-graph.md`, `design-docs/findings.md` |
| `internal/filed/` | A record filed under one issue read as another. See `design-docs/findings-issues.md` § Merged issues |
| `internal/rating/` | A product's own rating of an issue, in a query. See `design-docs/findings-severity.md` |
| `internal/cvss/` | CVSS 3.0, 3.1 and 4.0 base scores and bands, with no database. See `design-docs/findings-severity.md` |
| `internal/triage/`, `internal/advisory/` | Decisions, approvals, the CSAF document. See `design-docs/triage.md` |
| `internal/access/`, `internal/signin/` | Subjects and sign-in. See `design-docs/access.md`, `design-docs/access-signin.md` |
| `internal/notify/` | Notifications. See `design-docs/notifications.md` |
| `internal/weblink/` | Interface addresses the server hands out. See `design-docs/notifications.md` § Links |
| `internal/incident/` | Incident response windows, notices, the shelf. See `design-docs/incidents.md` |
| `internal/markdown/`, `internal/setting/`, `internal/currency/` | Text policy, administrator settings, upstream version lookups |
| `internal/attach/` | Files on an issue. See `design-docs/attachments.md` |
| `internal/trail/` | Changes to how this deployment works. See `design-docs/access-trail.md` |
| `internal/saved/` | Saved list narrowings. See `design-docs/interface-filters.md` |
| `internal/vex/`, `internal/publisher/` | VEX statements and who makes them. See `design-docs/remediation-vex.md` |
| `internal/directory/` | Issued advisories written for another web server. See `design-docs/remediation-directory.md` |
| `internal/csaf/` | CSAF provider description, ROLIE feed and provider lists. See `design-docs/remediation-csaf.md` |
| `internal/publish/` | Public security documents, revisions, and the publishing pass. See `design-docs/publishing.md` |
| `internal/httpapi/published/` | The surface serving them. See `design-docs/publishing.md` |
| `internal/signing/` | Signing with the operator's key. See `design-docs/publishing.md` |
| `internal/supplier/` | Supplier advisories read on a schedule. See `design-docs/ingest-suppliers.md` |
| `internal/upstream/` | Trusted upstreams and their VEX pass. See `design-docs/upstream.md` |
| `internal/cverecord/` | The CVE record snapshot. See `design-docs/findings-closure.md` § CVE record ranges and `design-docs/ingest-scanner.md` § CVE records |
| `internal/patchbranch/` | Branches holding a patch commit, repository copies, git's proxy. See `design-docs/findings-patch-branches.md` |
| `internal/vercmp/` | Version ordering per ecosystem. See `design-docs/remediation-versions.md` |
| `internal/outward/` | The one outbound HTTP client. See `design-docs/access-signin.md` |
| `internal/typedname/` | The stored form of a typed name. See `design-docs/data-model.md` |
| `internal/background/`, `internal/bound/` | Timed passes, and cutting a string without splitting a character |
| `internal/redact/` | A credential-bearing address made safe to log. See `design-docs/access-trail.md` § Secrets and logs |
| `internal/refusal/` | A caller-readable sentence, apart from a withheld fault. See `design-docs/api-refusals.md` |
| `internal/webui/` | The embedded interface. See `design-docs/interface.md` |
| `internal/weakness/` | Weakness catalog names. See `design-docs/findings-severity.md` |
| `internal/docs/`, `internal/build/`, `internal/tools/` | Document checks, makefile checks, and the gate, release, rehearsal and image-inventory programs |
| `web/` | The interface source. See `design-docs/interface.md` |
| `deploy/helm/openpsirt/` | The chart. See `design-docs/packaging-chart.md` |
| `docs/` | The documentation site |
| `assets/` | Logo files |
| `tools/` | One module per pinned Go tool. See `design-docs/build-dependencies.md` § Tool pins |
| `Makefile` | Build, tests, linter, gate, `check`, interface build, measurements, cleanup. It includes every other makefile after its own targets, so its first target stays the default |
| `mk/engines.mk` | The test database servers, and `check-engines` |
| `mk/gates.mk` | Vulnerabilities, licenses, inventory, credentials, gate programs, generated-file drift, pinned pairs |
| `mk/dist.mk` | Release assets and the release migration record |
| `mk/packaging.mk` | Image and chart checks |
| `Makefile.demo` | The demo, the hot-reload loop and the offline scanner bundle, kept apart from the gate half |

| Rule | Reason |
|---|---|
| Everything is under `internal/` | Nothing is importable by another module |
| Each makefile declares its own targets phony, and a test fails on a makefile no include names | |
| `internal/database` cannot read a setting | `internal/setting` imports it |
| The schema's tests cannot reach the harness's table list | They are an external test package |

## Make targets

Every CI check is a `make` target, reproducible locally with the same pinned
tools (REQ-75). The Go package pattern is `go list` minus `node_modules`, never
`./...`, which would compile and scan a Go package an npm dependency ships.

| Target | Runs |
|---|---|
| `make build` | The binary, with version information |
| `make gate` | The checks this change must pass, chosen from what it touches |
| `make gate full` | Every check |
| `make test` | SQLite only, parallel, cached |
| `make test-all` | Every configured engine, uncached: the two runs below, at once |
| `make test-race` | SQLite with the race detector |
| `make test-engines` | The three server engines, without the detector |
| `make docs-check` | What a documents-only change can break |
| `make lint` | Static analysis |
| `make vet-other-os` | Type-checks for macOS, and the upload client for Windows |
| `make client-test` | The upload client's tests, uncached; `make client-packages` and `make client-sources` print the lists the macOS and Windows jobs read |
| `make govulncheck` | Go vulnerabilities the change introduces |
| `make licenses` | Shipped Go and npm licenses against the allowlist |
| `make web-audit` | npm vulnerabilities the change introduces |
| `make secrets` | Credentials in tracked and unignored files |
| `make openapi` | Regenerates the API document |
| `make openapi-current` | The committed API document against the code |
| `make sbom` | This project's CycloneDX inventory |
| `make web-check` | Interface install, type check, formatting, linters, tests with coverage, class-name checks, generated client against the API document. Refuses without npm |
| `make unreachable` | Exported code nothing reaches. Functions, types, constants and variables by package and name through imports; methods by name alone. A test counts as a caller |
| `make negatives` | A 404 built from or detailed with an error's text, in any spelling the parsed Go allows: the error's method, a value named like an error, or a name bound earlier in the declaration |
| `make granted` | A function reaching one grant table reaches the other, through the table name, a model's struct tag, a type built from the model, or a package-level name's value. Exempt functions are named with reasons; an exemption matching nothing fails |
| `make narrowed` | A build resolved for a case-only participant is read with a subject or refused first. Bound resolutions and values derived from them are followed; inline uses are not |
| `make subjected` | An exported finding, triage or graph store method that queries without a subject, unless exempt with a reason. Queries are followed within the package by name; another package's are not seen |
| `make attached` | A doc comment describing a different declaration |
| `make confined` | Engine-specific code outside its two allowed places |
| `make readable` | Source files a text tool will not read |
| `make unclaimed` | Every requirement named by a design document |
| `make vendored` | Copied files accounted for. See `design-docs/build-dependencies.md` § Copied files |
| `make spdx` | License headers; `make spdx-fix` writes missing ones. See `design-docs/build-dependencies.md` § License headers |
| `make pins-check` | Versions pinned in two files agree |
| `make go-version` | The image's Go release, which every workflow installs |
| `make check` | Everything above. Needs npm |
| `make check-engines` | All four engines ran as claimed, and the reserved-word list matches them |
| `make reserved-words` | Rewrites the asked half of the reserved-word list from the engines |
| `make weakness-names` | Rewrites weakness names and primary parents from the catalog. In no gate, since the catalog is unpinned |
| `make cppcheck-weaknesses` | Rewrites cppcheck's check-to-weakness table from `cppcheck --errorlist`. In no gate; `CPPCHECK` names the binary |
| `make clang-checkers` | Fails on each clang C checker the weakness table lacks. Run per clang release; `CLANG` names the binary |
| `make reserved-current` | The committed reserved-word list against the engines, inside `check-engines` |
| `make check-packaging` | The image and chart. Needs `$(DOCKER)`, docker unless set, and helm; without either it prints that docker or helm is not installed and passes unchecked |
| `make dist` | Every release asset into `bin/dist`, checked against the tag. Refuses without docker, helm and npm. See `design-docs/packaging-release.md` § Release assets |
| `make release-freeze VERSION=vX.Y.Z` | The release migration record and its check, on a branch from `main` with four engines up. See `design-docs/database-migrations.md` § Release records |
| `make release-check VERSION=vX.Y.Z` | The tagged release was frozen and the tree still matches. The release workflow runs it first |
| `make docs-site` | The documentation site, strict. Needs mkdocs |
| `make engines-up` / `-down` / `-status` | The four database servers |
| `make engines-clean` | Drops unheld test databases. See `design-docs/build-tests.md` § Test databases |
| `make measure` | Measurements behind a build tag. See `design-docs/build-tests.md` § Measurement databases |
| `make sbom-shape` | The reader over a full-size committed inventory. Inside `check` |

## Gate tiers

`make gate` runs the tiers the working tree's changes land in, because a full
run for a prose edit teaches people to skip it (REQ-75). Tiers accumulate.

| Touched | Adds |
|---|---|
| `*.md` alone | `docs-check`, `unclaimed`, `pins-check`, `readable`, `secrets` |
| `web/**` alone | `web-check`, `spdx`, `readable`, `secrets` |
| the interface's manifest, lockfile or source | `licenses` too |
| the interface's route table | the Go tier too, since a Go test holds server links to it |
| Go reaching no SQL | `build`, `lint`, `vet-other-os`, `unreachable`, `readable`, `negatives`, `confined`, `granted`, `narrowed`, `subjected`, `attached`, `vendored`, `spdx`, `pins-check`, `sbom-shape`, `secrets`, `test` |
| a query, the schema, a migration, or the shared test harness | `reserved`, `test-all`, `check-engines` |
| Go the API document is generated from: the registering package, or a field with a description | `openapi-current`, `web-api` |
| `go.mod` or `go.sum` | `govulncheck`, `licenses`, `sbom`, and the engines tier |
| a tool's module under `tools/` | the whole gate |
| a gate program under `internal/tools/`, the shared repository reader included | the whole gate (§ Gate inputs) |
| anything else, or nothing | the whole gate |

| Rule | Reason |
|---|---|
| A program chooses the tier | |
| An unclassified path takes the whole gate | The makefile, container, chart, assets and fixtures |
| A Go file is classified by its whole content | An edit anywhere in a file of queries can move a query |
| A file takes every tier it lands in | |
| Every tier reachable alone scans for secrets | A pushed credential is in the remote's history |
| Every target `check` runs is in some narrow tier, held by a test | |
| `docs-check` tests every package whose tests read a `.md` file, held by a test | |
| A clean tree takes the whole gate | It is about to push committed work |
| `test-all` replaces `test` | |
| Local and CI run the identical command | |
| `openapi-current`, `web-api` and `reserved-current` pass only on a commit | Each diffs a regenerated file against it |
| Test code behind a build tag is linted with the tag | Nothing else compiles it, so a rename breaks it silently |
| A test behind an environment variable has a target in `check` setting it | |

## CI jobs

| Job | Holds | Separate because |
|---|---|---|
| Build, test and check | `engines-check`, `make check`, `check-engines`, the bill of materials as an artifact | — |
| Container image and chart | The image, then `check-packaging` | buildx, helm and a build cache |
| Documentation builds | The site | Python |
| Upload client on macOS and Windows | `client-test` per system, after a Linux step compares the change with `client-sources` | Only there are the client's paths and line endings seen as a build host sees them |

| Rule | Reason |
|---|---|
| The first job runs `make check`, never a target list | A target added to `check` runs in CI |
| Jobs needing only a checkout and Go are one job | |
| No composite action or reusable workflow | One Go setup remains, and a reusable workflow re-clones |
| The macOS and Windows jobs run only when a client source moved | Those runners cost several Linux ones |
| `client-sources` is what reaches the client, held by a test in `internal/build` | It includes fixtures the client's tests read and the Dockerfile, whose `golang` tag sets the runners' Go |
| No make on Windows: the Linux step prints the packages and Go release for `go test` | |
| A skipped job satisfies the merge check | Queue entries and pull requests compare against their own base |
| `Merge Status`, a job in the `PR` workflow, is the one check the ruleset requires; it waits for every other check to pass or be skipped | |
| `Release` runs on a tag (`design-docs/packaging-release.md` § The release procedure) | |
| Every gating workflow declares `merge_group:` | Without it a queue entry gets no check, which looks unstarted |
| `Dependabot` runs on pull requests alone, skipped on any Dependabot did not open or push (`design-docs/build-dependencies.md` § Action pinning) | It queues; it gates nothing |
| Documentation publishing is its own workflow, on `main` alone | It writes to the repository |
| Dependency review is not run | It needs paid Advanced Security on a private repository; `licenses`, `web-audit` and `secrets` cover it and run locally (REQ-75) |

### CI caches

| Cache | Holds | Keyed on | Saved |
|---|---|---|---|
| Go modules | Modules for the tree and pinned tools | `go.sum` and each tool's | When the key is new |
| Go build | Plain and race builds, test objects, tools built from source | The run, restored by prefix | On `main` |
| Linter results | Per-package analysis by content | The run, restored by prefix | On `main` |
| Image layers | Every stage's layers | The buildkit scope | On `main` |

| Rule | Reason |
|---|---|
| A pull request restores all four and saves none | Its saves are keyed to a commit nothing rebuilds, and the 10 GB store evicts least recently used |
| The build and linter caches keep only what the run read: entries are moved two hours back first, and unmoved ones deleted after | Both tools refresh an entry's time once it is an hour old. Saved whole, the build cache is 2.87 GB against 683 MB |
| Linter results are keyed by package content | One changed file costs 9 to 12 s against 42 s with none, on four local cores |
| The image's Go steps mount the build cache, never write it into a layer | A layer after the source copy is per commit: 441 MB and 499 MB became 39 MB and 131 kB |
| The bill-of-materials tool is fetched beside `go mod download`, before the source copy | Its layer is reused |

`design-docs/build-measurements.md` § CI caches has the runs.

## Gate inputs

Every gate program walks the repository through one reader, which skips the
version history, local scratch, a local tool's worktrees, vendored code and the
three output directories. Each caller names what else it skips, with the reason:
the Go gates skip the TypeScript interface; the text-encoding gate skips a vendor
directory and reads the interface.

| Rule | Reason |
|---|---|
| A walk reaching nothing refuses | Reading nothing looks like finding nothing |
| The count is of what the caller kept, never what it was shown | |
| Every gate prints how much it read | |
| A skipped directory is matched by name at any depth | Nested dependency directories are covered |
| A change to the reader takes the whole gate | It decides what every check reads |

## Static analysis

| Rule | Reason |
|---|---|
| `.golangci.yml` alone selects rules, each gating or advisory | No scope grandfathers a backlog (REQ-75) |
| Documentation rules are off; error checking excludes conventional cleanup calls | |
| The linter's `govet` is the vet, over test files and the `measure`-tagged file | Running `go vet` too cost 50 s of a two-core runner |
| A test holds that configuration: `govet` on and unnarrowed, test and generated files included, no exclusion naming either, the `measure` tag passed | The linter skips generated files by default |
| The linter reports one issue per line | |
| The linter's Go release is at least the code's | Otherwise it cannot read export data (`design-docs/build-dependencies.md` § Pinned pairs) |

## The API document

| Rule | Reason |
|---|---|
| Generated from the registered operations, never written by hand (REQ-61) | |
| CI fails where the committed copy differs | Each operation's required rights ride on it (REQ-62), so access changes show in the diff |
| The application serves it, authenticated, and nothing that renders it (REQ-63) | |

## Probes

| Rule | Reason |
|---|---|
| `/healthz` and `/readyz` answer without authentication, outside the documented API, and never describe contents | A container probe cannot sign in |
| The sign-in paths and interface assets also need no credential and read nothing the deployment holds (REQ-43) | The published security documents are the one exception (`design-docs/publishing.md`) |

`design-docs/packaging-chart.md` § Chart probes says how the chart uses them.

## The review checklist

The checklist in `AGENTS.md` is worked through on every review (REQ-75). CI
checks what a machine can, so the checklist holds the rest.

## Repository settings

| Setting | Needed by | Symptom when off |
|---|---|---|
| Every change through a pull request, no direct push to `main` | The gate | A commit reaches `main` unchecked |
| Merge queue, squash, `ALLGREEN` | Landing what was tested | A pull request green against an old `main` |
| One required check, `Merge Status` | Every other check | A new workflow gates nothing |
| Dependabot alerts | Vulnerabilities between changes | Nothing reports a bad dependency |
| Actions pinned to a SHA (`design-docs/build-dependencies.md` § Action pinning) | Reviewed action code only | A moved tag executes here |
| Pages, serving `gh-pages` | Documentation | The workflow succeeds and nothing is served |

| Rule | Reason |
|---|---|
| Secret scanning, push protection and dependency review are off | Paid per committer on a private repository; local targets replace them |
| A private Pages site is served only to readers of the repository, at a generated address | |

## Limits

| Limit | Detail |
|---|---|
| History is not scanned for credentials | A removed credential stays in the objects. Push protection and history scanning are free once public |
