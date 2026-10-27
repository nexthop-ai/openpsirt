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

`make pins-check` compares every version written in two files, which answers
what a release is built from, where the engine check answers what tests run
against. It also catches an image carrying two defaults for the version passed
in, whose build with none reports `dev` in the binary and `0.0.0` in its
inventory.

| Rule | Reason |
|---|---|
| The image's `golang` tag is the one pin of the Go patch release | One number to move, in the file Dependabot's image update edits. A floating base cannot tell patches apart, so a tarball and an image of one commit would be built by two toolchains |
| Every workflow installs the release `make go-version` reads from that tag | The tarball, the image and the tests share one toolchain |
| `go.mod`'s `go` line is held at or below the image's release, compared as versions, and a line above it fails | It is the oldest release the module accepts, and held equal an image bump would fail until `go.mod` was edited by hand. A module needing a newer Go lands after the image moves |
| Each tool's module under `tools/` is held to the same `go` line rule | The image and the workflows build the tools with the image's release |
| The image's `node` tag is the one pin of the interface's Node, and every workflow installs the release `make node-version` reads from it | Moving the tag moves the interface's toolchain everywhere |
| A workflow naming a Node release itself fails | A second copy is the one a bump leaves behind |
| The Python the documentation lock was resolved on is the one the workflows build it with | A second Python resolves a different closure |
| The `modernc.org/libc` the build selects is the one `modernc.org/sqlite` requires | The driver is generated against one libc release, and libc's notes ask for that release only. Another module requiring a newer one moves it by minimal version selection with no line here changing: goose 3.29.0 requires a newer libc than sqlite 1.60.1, so Dependabot ignores goose from there until sqlite moves |
| The quota a chart's scratch space is sized for is held to the binary's built-in quota | `design-docs/packaging.md` § Repository copies |

| Cost | Answered by |
|---|---|
| The image no longer picks up a Go release by itself | Dependabot's pull request moving the `golang` tag moves the toolchain everywhere and passes `pins-check` alone. The tag is grouped alone, so an image bump held red never holds the standard library's fixes |
| A pinned toolchain goes stale between bumps | `govulncheck` reports standard-library vulnerabilities against it, and the image update carries the fix |
| A Go release can write export data the pinned linter cannot read, failing it on every package | The tools' weekly update brings the linter that reads it, and lands first. Go 1.27.2 writes format 5, which golangci-lint v2.14.0 is the first to read |

## Tool pins

Every Go tool the gate or the image runs is required by a module of its own
under `tools/`, and run with `go tool` against that module.

| Rule | Reason |
|---|---|
| A tool's version is a requirement in its module's `go.mod`, and its `go.sum` checksums everything it is built from | Dependency updates read requirements; a version in the makefile is one nothing moves |
| One module per tool | Moving one tool never moves a library another is built against |
| A build-constrained source file imports the tool's command | The requirement is then direct, which is what the updates move |
| A tool's directory is named for the command its module declares, and `pins-check` refuses one that is not | The targets call a tool by its directory |
| The image builds the inventory generator from the module the makefile runs | One pin, read by both |

| Tool | Run by |
|---|---|
| golangci-lint | `make lint`, `make fmt` |
| govulncheck | `make govulncheck` |
| go-licenses | `make licenses` |
| gitleaks | `make secrets` |
| cyclonedx-gomod | `make sbom`, and the image's inventory of its binary |

## Hash pinning per ecosystem

| Ecosystem | What names the bytes |
|---|---|
| Go | `go.sum`, and each tool's under `tools/`, through the checksum database |
| Node | `package-lock.json`, by integrity |
| Python, for the documentation | `docs/requirements.txt`, a lock with a hash for every package in the closure, installed with `--require-hashes` |
| The scanner and the cataloger | A version and a per-architecture hash in the image |
| Actions | A commit, never a tag |

| Rule | Reason |
|---|---|
| The whole Python closure is hashed | It runs beside a token that can write to the repository, and a republished transitive release would execute on the next push |
| Direct versions are written in `docs/requirements.in`, and the lock is generated, never edited | |
| `pins-check` asks that every locked package carries a hash, each direct version is the one resolved, every installing workflow passes `--require-hashes`, and they agree on one Python | |
| An upstream republishing fails the install closed | It is answered by regenerating the lock in a reviewed commit |

```
pip-compile --generate-hashes --output-file docs/requirements.txt docs/requirements.in
```

## Known vulnerabilities

`make govulncheck` and `make web-audit` fail a change for a known vulnerability
it introduces, and report without failing one already on the branch it targets
(REQ-75).

| Rule | Reason |
|---|---|
| The base is where this branch left the branch it targets | `AUDIT_BASE` names that branch, `origin/main` unless set. CI fetches full history so the common commit is there |
| An advisory is present when the base was already affected by it, and introduced otherwise | A bump fixing one advisory and leaving another introduces nothing, so its security update stays green |
| A Go finding is present when the base's `go.mod` version falls in the advisory's affected ranges | `go.mod` names every module a build uses, and each advisory carries its ranges |
| A standard-library finding is present when the base's Dockerfile Go release falls in the affected ranges | That tag is the toolchain every workflow installs. `go.mod`'s `go` line stands in only where the base's Dockerfile names no release |
| An npm advisory is present when npm's audit of the base's lockfile names it against the same package | npm's ranges are npm's to read. A package moved in the tree, or bumped to a version still affected, was affected before |
| Anything the base does not hold is introduced | A new dependency arrives with whatever is known against it |
| A Go finding gates when a called function reaches it | govulncheck's own line |
| An npm advisory gates at high and above | `npm audit --audit-level=high`'s line |
| A package listed only because something beneath it is affected carries no advisory | npm lists every package on the path, which counts one advisory many times |
| No common commit with the base refuses, in words | Every advisory would read as introduced, or none |
| A govulncheck run exiting non-zero refuses, with its standard error | Its JSON mode exits zero whatever it finds and prints its configuration before loading, so a failed scan can read as clean |
| A govulncheck inventory naming no module refuses | An empty package list scans nothing and exits zero |
| Both npm audits read the lockfile alone | npm otherwise audits the installed tree, stale in a checkout not reinstalled since a bump |
| A file the base lacks is decided by a listing of the base's tree | git's message for a missing path varies with the working tree and the locale |
| An npm run whose output is not a report refuses, with npm's message where it gave one | npm exits non-zero whenever it finds anything, and offline it prints a message for a report |
| On the base branch itself nothing is introduced | The common commit is the commit checked, so a push to `main` reports and does not fail |

An advisory already on the base blocks neither `main` nor a release, and reaches
a fix through a Dependabot pull request:

| Advisory against | Fixed by |
|---|---|
| A Go module | The weekly `gomod` update, grouped |
| The Go standard library | The weekly image update moving the `golang` tag |
| An interface package | The weekly `npm` update of `web/`, grouped |
| A documentation build package | The weekly `pip` update of `docs/`, regenerating the hashed lock |

## Licenses

Permitted for shipped dependencies: Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
MIT, MPL-2.0 (REQ-01). `make licenses` checks what the module links and what npm
installs.

| Rule | Reason |
|---|---|
| Both ecosystems are checked against one allowlist, `ALLOWED_LICENSES`, passed in | The interface is built into the binary, so what npm installs ships as a Go module does |
| Development dependencies are unrestricted on both sides | A build tool binds whoever builds, never whoever installs |
| Build tooling is exempt | The linter is GPL; running a tool affects the code's license no more than the compiler does |
| The npm half refuses a development dependency the interface's source imports | It is in the bundle: an import or re-export that is not type-only, a dynamic import, or a stylesheet `@import` naming a development package. Tests and the test harness are not read. A bundled package is declared a dependency, where its license is checked |
| A run reading no import from the source refuses, as one finding no shipped dependency in the lockfile does | |
| A short exception list covers modules whose license the classifier cannot read, each naming the license and why the tool fails, read by hand before it is added | Lowering the classifier's threshold accepts every unreadable license silently |
| An exception names a package whole, wherever installed; a name ending in `/` names a scope | `argparse` admits neither `argparse-lite` nor `@someone/argparse` |
| An SPDX expression is evaluated: `MIT AND ISC` needs both allowed, `(MPL-2.0 OR Apache-2.0)` either | Matched as a string it is refused, and listing the string accepts every expression spelled that way |
| An expression read to anything short of its end, an unclosed group included, is refused | |

| Exception | Reason |
|---|---|
| `@fontsource/*` under OFL-1.1 | The license fonts are published under; it withholds selling the fonts alone |
| `argparse` under PSF-2.0 | A port of Python's argparse carrying its license. Permissive, and compatible |

## Copied files

`make vendored` checks what is copied into the tree: a version suite from
another project, a specification's example document, a publisher's advisory, a
table transcribed from a reference implementation, a generated catalog. Each is
in one list with its origin and the license its source states.

| Rule | Reason |
|---|---|
| A file is found in the tree, then looked for in the list | Every file under a `testdata` directory, and every file carrying a copyright line not this project's, a license identifier, a document's data license, or a comment saying `NOTICE` records it. A file copied in with no line fails the gate |
| This project's own header is not a mark | A file carrying this project's copyright is ours; any other identifier in it is still somebody else's terms |
| Found broadly, and a file written here is listed as ours | A file the search misses is one nobody is asked about |
| A line is held only where its file needs it, or `NOTICE` names it | A stale line would hold whatever is copied to that path next |
| Not searched: `NOTICE` and `LICENSE`, markdown, files that are not text, and the gate's own source and list | The last two spell every mark it looks for |
| Held to a license this tree may carry | The dependency allowlist, plus the licenses data is published under: a public-domain dedication, CC-BY-4.0, and the weakness catalog's terms. Expressions are evaluated as for dependencies: AND binds tighter than OR, parentheses group, an unparsed expression is refused |
| Named in `NOTICE` where the license asks for attribution | Every license here but a public-domain dedication asks |
| Every path `NOTICE` names is in the tree and held as somebody else's | A removed or renamed file leaves no attribution pointing at nothing |
| A file's license is read by a person | A data file states its license in its own words, if at all; the list records what somebody read |

## License headers

Every source file opens with this project's copyright and an SPDX identifier,
checked by `make spdx` and written where missing by `make spdx-fix`.

    // Copyright Nexthop Systems Inc.
    // SPDX-License-Identifier: Apache-2.0

| Rule | Reason |
|---|---|
| Source is Go, TypeScript, JavaScript, CSS, shell, Python, a makefile and a Dockerfile | The files a license scanner reads as code |
| Each writes it in its own comment | Two slashes, a slash-star pair per line in CSS, a hash elsewhere |
| It comes first, after only an interpreter line or a Dockerfile's parser directives, and a blank line follows it | Those are read only from the top, and the blank line keeps a Go package comment attached |
| A file carrying somebody else's work states their terms beside this tree's own | The expression joins this license with the one the copied-files list holds, so the two gates agree |
| A fixture and a file a third party's tool writes whole carry none | A fixture is accounted for as a copied file, and a generated file loses the header on every write; this project's generators write it themselves |
| A wrong header is reported, never rewritten | Which is right is a person's to read |
| No year | The dated notice is in `NOTICE`; a year per file is touched every January or wrong |

## Action pinning

| Rule | Reason |
|---|---|
| Every action is pinned to a release's commit, with the version in a comment | A tag moves, and a moved action runs with this repository's token on a day nobody chose |
| The repository requires it: `sha_pinning_required` refuses an action by tag | Enforced, never remembered |
| Dependabot moves the pins weekly, one pull request per group: actions, images, the `golang` image alone, the database layer's Go modules, other Go modules, the Go tools, interface packages, the documentation closure | A pin nobody moves stops receiving fixes silently; ungrouped they are noise |
| The database layer's modules, the query builder, drivers and migration runner, are a group of their own | A release there can change an interface every store is written against: bun v1.3.0 makes every limit, offset and count an int64 |
| The interface group carries minor and patch releases; a major release is a pull request of its own | A major release needs work, which then holds nothing back |
| TypeScript's major releases are not offered | The linter's TypeScript support and the API client generator each accept a range of compilers, neither includes 7, and npm refuses the install. It lifts when both do |
| An update arrives through the queue like anything else | The pinned commit is in the diff, and the gate runs against it |

## Limits

| Limit | Detail |
|---|---|
| A new call into an affected function of an unchanged module is not introduced | The module was already affected and reported |
| A scanner and inventory tool pinned by build argument are watched by nobody | `design-docs/packaging.md` § Limits |
