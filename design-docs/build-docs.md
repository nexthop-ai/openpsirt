# Documentation build

The published documentation site, its versioned sets, and the checks held over
every document: links, make commands, release versions, scanner pins and the
settings reference.

Satisfies REQ-63.

## Contents

- [Documentation](#documentation)
- [Link check](#link-check)
- [Release version](#release-version)
- [Scanner pins](#scanner-pins)
- [The settings reference](#the-settings-reference)
- [Limits](#limits)

## Documentation

Built with mkdocs-material and published to GitHub Pages, with sets versioned by
`mike` (REQ-63).

| Set | Published by |
|---|---|
| `main` | Every push to `main` |
| Each release, by version | The release workflow, which moves `latest` to the newest release (`design-docs/packaging-release.md` § The release procedure) |

| Rule | Reason |
|---|---|
| The site's default is `latest` once a release carries it, and `main` until then | A visitor reads the root first, and unreleased documentation there describes a version nobody can install |
| A push to `main` sets the default to `latest` where a set carries it, and to `main` where none does | A default another run moved is put back on the next merge |

## Link check

A test in `internal/docs` follows every link in every document and fails on one
reaching nothing. A test in `internal/build` holds every make command a document
names to the makefiles.

| Rule | Reason |
|---|---|
| A fragment is checked against the anchors its own page's renderer derives | A link is followed where its page is read |
| A page under `docs/` is held to the site's rule: decomposed to ASCII, punctuation removed, each run of spaces and hyphens one hyphen | The table-of-contents extension's default |
| Every other document is held to the forge's rule: punctuation but the underscore removed, each space a hyphen | A heading separated by a dash takes two hyphens there and one on the site |
| A link to a directory or another kind of file is checked for existence, whatever fragment, query or title follows | A renamed `LICENSE` or `docs/` dangles a link too |
| A link in a code fence or inline code span is not read | It renders no link |
| A make command is read inline in backticks, and on a line of its own in a fenced block, after a prompt or variables set for the run | A block is what a reader copies. Prose outside one is not read by line, because "make the claim" opens a line as readily as a command |

## Release version

A page names the release a reader deploys as `{{ release }}`, and the build
writes the version in.

| Build | Version written in |
|---|---|
| A release tag, published by the release workflow | The tag's version, passed as `DOCS_RELEASE`. A release candidate's pages name the candidate |
| `main`, published on every push | The newest release tag reachable from the commit, candidates left out |
| The CI check and a local `make docs-site` | As for `main` |
| None of those resolves | The build fails; a blank or default version is a command somebody copies |

| Rule | Reason |
|---|---|
| A version is `X.Y.Z` or `X.Y.Z-rc.N`, with or without a leading `v`; anything else in `DOCS_RELEASE` fails the build | |
| Every workflow building the site checks out full history | A shallow checkout carries no tags |
| A test in `internal/docs` fails on a release version written by hand in `README.md`, `SECURITY.md` or a page under `docs/` | |
| `README.md` names no version | The site does not build it |
| The compatibility notes say a database any release built is upgraded in place, and one a release candidate built is recreated | The first holds while every release's migrations are kept; a candidate's migration can be fixed before release (`design-docs/database.md` § Migrations) |

| Not reported | Reason |
|---|---|
| The configuration page's upgrade notes: a `From vX.Y.Z` heading and everything beneath it | Past releases are their subject |
| Four numeric parts, or a version running into a letter | A network address, or a third party's package version |
| The versions an example on one page shows, listed by page in the test | A third party's version or a customer's tag |

## Scanner pins

The pages name what the Dockerfile's scanner stage pins, and the build writes it
in.

| Placeholder | Filled with |
|---|---|
| `{{ scanner }}` | The scanner version the image carries |
| `{{ scanner_sha256_amd64 }}`, `{{ scanner_sha256_arm64 }}` | The checksum the image build verifies each architecture's download against, so a host installing the scanner checks the same pin rather than the release's own checksum file |

| Rule | Reason |
|---|---|
| The hook declares every name a page may write | The build fails on a page writing another, and on a declared name it does not fill |
| Each pin is read from the scanner stage alone, and must appear there once | Another stage pins another tool's checksums the same way |
| A written-out scanner version is reported | It is a release-shaped literal |
| A workflow expression, `${{ … }}`, in a pipeline example is not a placeholder | It follows a dollar sign and holds a dot |
| A test in `internal/docs` reads the declared names from the hook | It fails on a page writing another, a declared name no page writes, and a pin the scanner stage holds other than once |

## The settings reference

The configuration page lists every setting the process reads, with its
environment variable, its configuration file key, its meaning and its default.
A set value that cannot be read stops the process naming the setting, never
falling back.

| Held by a test | Reason |
|---|---|
| Every variable the loader reads is on the page, and every variable on the page is read | Both directions, failing on zero examined |
| Every setting's file key is on the page in its variable's row, and no other key is | A key read into the wrong setting shows beside the wrong variable |
| The table of settings in code is what the loader reads | A name the loader asks for and the table lacks is settable from neither source |

## Limits

| Limit | Detail |
|---|---|
| `README.md` and `docs/index.md` are compared from their first section to the end of their deployment section, link targets set aside | Neither can include the other. Each links to the other pages by its own path |
