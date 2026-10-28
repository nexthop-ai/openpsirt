# Dependencies and supply chain

Pinned versions and the files that must agree on them, the Go tools, hash
pinning, known vulnerabilities, licenses, copied files, and action pins.

Satisfies REQ-01, REQ-75.

## Contents

- [Pinned pairs](#pinned-pairs)
- [Tool pins](#tool-pins)
- [Hash pinning per ecosystem](#hash-pinning-per-ecosystem)
- [Known vulnerabilities](#known-vulnerabilities)
- [Licenses](#licenses)
- [Copied files](#copied-files)
- [License headers](#license-headers)
- [Action pinning](#action-pinning)
- [Limits](#limits)

## Pinned pairs

`make pins-check` compares every version written in two files. It also catches
an image with two defaults for the version passed in, whose build reports `dev`
in the binary and `0.0.0` in its inventory.

| Rule | Reason |
|---|---|
| The image's `golang` tag is the one pin of the Go patch release | Dependabot's image update edits it, and a floating base would build a tarball and an image of one commit with two toolchains |
| Every workflow installs the release `make go-version` reads from it | |
| `go.mod`'s `go` line is at or below the image's release, compared as versions | Held equal, an image bump would need a hand edit; a module needing newer Go lands after the image moves |
| Each tool module under `tools/` follows the same `go` line rule | |
| The image's `node` tag is the one pin of the interface's Node, installed everywhere through `make node-version`, and a workflow naming a Node release fails | |
| The documentation lock's Python is the workflows' Python | Another resolves a different closure |
| The `modernc.org/libc` the build selects is the one `modernc.org/sqlite` requires, and `pins-check` fails otherwise | The driver is generated against one libc. Minimal version selection can move it silently: goose 3.29.0 needs a newer libc than sqlite 1.60.1, so Dependabot ignores goose until sqlite moves |
| The chart's repository-copy scratch size follows the binary's built-in quota | `design-docs/packaging.md` § Repository copies |

| Cost | Answered by |
|---|---|
| The image picks up no Go release by itself | Dependabot's `golang` tag update, grouped alone so a red image bump holds back no standard-library fix |
| The pinned toolchain goes stale between bumps | `govulncheck` reports its standard-library vulnerabilities |
| A Go release can write export data the pinned linter cannot read | The tools' weekly update lands the linter first: Go 1.27.2 writes format 5, first read by golangci-lint v2.14.0 |

## Tool pins

Every Go tool the gate or image runs is required by its own module under
`tools/` and run with `go tool`.

| Rule | Reason |
|---|---|
| The version is a requirement in the module's `go.mod`, checksummed in its `go.sum` | Dependency updates move requirements |
| One module per tool | A bump never moves another tool's libraries |
| A build-constrained file imports the tool's command | The requirement is direct, which updates move |
| A tool's directory is named for its command, enforced by `pins-check` | Targets call tools by directory |
| The image builds the inventory generator from the makefile's module | |

| Tool | Run by |
|---|---|
| golangci-lint | `make lint`, `make fmt` |
| govulncheck | `make govulncheck` |
| go-licenses | `make licenses` |
| gitleaks | `make secrets` |
| cyclonedx-gomod | `make sbom`, and the image's binary inventory |

## Hash pinning per ecosystem

| Ecosystem | What names the bytes |
|---|---|
| Go | `go.sum`, and each tool's, through the checksum database |
| Node | `package-lock.json`, by integrity |
| Python, for the documentation | `docs/requirements.txt`, hashing the whole closure, installed with `--require-hashes` |
| The scanner and the cataloger | A version and per-architecture hash in the image |
| Actions | A commit |

| Rule | Reason |
|---|---|
| The whole Python closure is hashed | It runs beside a token that can write to the repository |
| Direct versions live in `docs/requirements.in`; the lock is generated, never edited | |
| `pins-check` asks that every locked package has a hash, direct versions match the lock, every install passes `--require-hashes`, and one Python is used | |
| A republished package fails the install closed, answered by regenerating the lock in review | |

```
pip-compile --generate-hashes --output-file docs/requirements.txt docs/requirements.in
```

## Known vulnerabilities

`make govulncheck` and `make web-audit` fail a change for a vulnerability it
introduces, and report one already on its target branch (REQ-75).

| Rule | Reason |
|---|---|
| The base is the merge base with `AUDIT_BASE`, `origin/main` unless set; CI fetches full history | |
| An advisory is present when the base was affected, and introduced otherwise | A bump fixing one advisory of two stays green |
| A Go finding is present when the base's `go.mod` version is in its affected ranges | |
| A standard-library finding is present when the base Dockerfile's Go release is in its ranges, or `go.mod`'s `go` line where the Dockerfile names none | That tag is every workflow's toolchain |
| An npm advisory is present when npm's audit of the base lockfile names it for the same package | A moved or still-affected package was affected before |
| Anything the base lacks is introduced | |
| A Go finding gates when a called function reaches it | |
| An npm advisory gates at high and above | |
| A package listed only for an affected dependency carries no advisory | Otherwise one advisory counts many times |
| No merge base refuses | |
| govulncheck exiting non-zero refuses, with its standard error | Its JSON mode exits zero whatever it finds |
| A govulncheck inventory naming no module refuses | It scanned nothing |
| Both npm audits read the lockfile alone | The installed tree may be stale |
| A file missing from the base is decided by listing the base's tree | git's message varies with the working tree and locale |
| An npm run whose output is no report refuses, with npm's message | npm exits non-zero on any finding, and offline prints a message |
| On the base branch itself nothing is introduced | A push to `main` reports and passes |

An advisory already on the base blocks neither `main` nor a release, and is fixed
by Dependabot:

| Advisory against | Fixed by |
|---|---|
| A Go module | The weekly `gomod` group |
| The Go standard library | The weekly image update moving the `golang` tag |
| An interface package | The weekly `npm` group for `web/` |
| A documentation build package | The weekly `pip` update regenerating the lock |

## Licenses

Permitted for shipped dependencies: Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
MIT, MPL-2.0 (REQ-01). `make licenses` checks Go and npm against one
`ALLOWED_LICENSES`, since the interface ships inside the binary.

| Rule | Reason |
|---|---|
| Development dependencies are unrestricted | A build tool binds whoever builds |
| Build tooling is exempt; the linter is GPL | Running a tool does not license the code |
| The npm half refuses a development dependency the interface's source imports: a non-type-only import or re-export, a dynamic import, a stylesheet `@import` | It is in the bundle. Tests are not read |
| A run reading no import, or finding no shipped dependency, refuses | |
| An exception names a module the classifier cannot read, with the license read by hand and why the tool fails | A lower threshold accepts every unreadable license |
| An exception names a package whole, or a scope with a trailing `/` | `argparse` admits neither `argparse-lite` nor `@someone/argparse` |
| An SPDX expression is evaluated: `MIT AND ISC` needs both, `(MPL-2.0 OR Apache-2.0)` either; one not parsed to its end is refused | |

| Exception | Reason |
|---|---|
| `@fontsource/*` under OFL-1.1 | It withholds only selling the fonts alone |
| `argparse` under PSF-2.0 | A port of Python's argparse under its permissive license |

## Copied files

`make vendored` checks files copied into the tree, such as a version suite, a
specification's example, a publisher's advisory, a transcribed table or a
generated catalog, against one list giving each one's origin and stated license.

| Rule | Reason |
|---|---|
| Files are found in the tree, then looked up in the list | Every file under `testdata`, and every file with a foreign copyright line, a license identifier, a data license, or a comment saying `NOTICE` records it. An unlisted one fails |
| This project's own header is not a mark; any other identifier beside it is | |
| A file written here that the search finds is listed as ours | |
| A line is kept only where its file needs it or `NOTICE` names it | A stale line would cover the next file copied there |
| Not searched: `NOTICE`, `LICENSE`, markdown, non-text files, the gate's source and list | The last two spell every mark |
| The license must be allowed: the dependency allowlist plus a public-domain dedication, CC-BY-4.0 and the weakness catalog's terms, expressions evaluated as for dependencies | |
| `NOTICE` names every file whose license asks for attribution, which is all but a public-domain dedication | |
| Every path `NOTICE` names exists and is listed as somebody else's | |
| A person reads each license and records it | Data files state theirs in their own words |

## License headers

`make spdx` checks that every source file opens with this project's copyright
and an SPDX identifier; `make spdx-fix` writes missing ones.

    // Copyright Nexthop Systems Inc.
    // SPDX-License-Identifier: Apache-2.0

| Rule | Reason |
|---|---|
| Source is Go, TypeScript, JavaScript, CSS, shell, Python, makefiles and Dockerfiles | |
| Each uses its own comment: two slashes, slash-star per line in CSS, a hash elsewhere | |
| It comes first, after only an interpreter line or Dockerfile parser directives, followed by a blank line | The blank line keeps a Go package comment attached |
| A file with somebody else's work joins their license from the copied-files list | The two gates agree |
| Fixtures and files a third-party tool writes whole carry none; this project's generators write it | |
| A wrong header is reported, never rewritten | |
| No year; the dated notice is in `NOTICE` | |

## Action pinning

| Rule | Reason |
|---|---|
| Every action is pinned to a release commit, its version in a comment | A tag can move under this repository's token |
| `sha_pinning_required` refuses an action by tag | |
| Dependabot moves pins weekly in groups: actions, images, the `golang` image alone, database-layer Go modules, other Go modules, Go tools, interface packages, the documentation closure | |
| The database layer, the query builder, drivers and migration runner, is its own group | Its releases change interfaces every store uses: bun v1.3.0 made limits, offsets and counts int64 |
| Interface minor and patch releases are grouped; a major release is its own pull request | |
| TypeScript majors are not offered | The linter's TypeScript support and the API client generator both refuse 7. It lifts when both accept it |
| Updates go through the merge queue | |
| A minor or patch update is approved and queued as it opens and after each rebase, by the `Dependabot` workflow | The queue runs the whole gate; a push dismisses an approval |
| A major update, the actions group and a dependency whose maintainers changed wait for a person | A major release needs code; an action runs with the repository's token; a maintainer change is what a takeover looks like |
| An approval refused, because the repository does not let Actions approve, warns and still queues | Where no approval is required it merges |

## Limits

| Limit | Detail |
|---|---|
| A new call into an affected function of an unchanged module is not introduced | The module was already reported |
| The scanner and inventory tool pins are watched by nobody | `design-docs/packaging.md` § Limits |
| An update the `Dependabot` workflow queues may merge without starting `main`'s push workflows | GitHub starts no workflow for an event the job's own token causes, so the documentation publish and the caches wait for the next merge |
